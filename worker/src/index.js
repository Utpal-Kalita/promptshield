// PromptShield backend: a thin proxy over the Clocked API.
// The browser never sees the API key. Every analysis runs the three
// safety endpoints (Protect/pii, Guard/injection, Inspect/script) and
// returns their raw verdicts plus a normalized summary.

const CLOCKED_BASE = 'https://clocked.rezolve.ai/clocked';

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

// Bounded abuse control: the site is public, and every analysis spends the
// owner's free Clocked credits. A daily global cap plus a per-visitor cap keep
// total spend bounded even if someone scripts against the API directly.
// CORS is not authentication, so this lives server-side in KV.
const GLOBAL_DAILY_CAP = 60;
const IP_DAILY_CAP = 15;

async function rateCheck(env, ip) {
  const day = new Date().toISOString().slice(0, 10);
  const gk = `rl:global:${day}`;
  const ik = `rl:ip:${ip}:${day}`;
  let g;
  let i;
  try {
    [g, i] = await Promise.all([env.RATE_LIMIT.get(gk), env.RATE_LIMIT.get(ik)]);
  } catch {
    return { ok: false, status: 503, reason: 'rate limiter unavailable, try again shortly' };
  }
  if (parseInt(g || '0', 10) >= GLOBAL_DAILY_CAP) {
    return { ok: false, status: 429, reason: 'demo capacity reached for today, please come back tomorrow' };
  }
  if (parseInt(i || '0', 10) >= IP_DAILY_CAP) {
    return { ok: false, status: 429, reason: `limit of ${IP_DAILY_CAP} analyses per day per visitor` };
  }
  const ttl = 90000;
  await Promise.all([
    env.RATE_LIMIT.put(gk, String(parseInt(g || '0', 10) + 1), { expirationTtl: ttl }),
    env.RATE_LIMIT.put(ik, String(parseInt(i || '0', 10) + 1), { expirationTtl: ttl }),
  ]);
  return { ok: true };
}

function splitPassages(text) {
  // Paragraphs first, then long ones fall back to sentence-ish chunks.
  const raw = text.split(/\n{2,}|(?<=\.)\s+(?=[A-Z])/);
  const passages = [];
  for (const piece of raw) {
    const t = piece.trim();
    if (t.length >= 20) passages.push(t.slice(0, 1500));
    if (passages.length === 20) break;
  }
  return passages;
}

async function directClockedCall(env, path, payload, idemKey) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  try {
    const res = await fetch(`${CLOCKED_BASE}${path}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.CLOCKED_API_KEY}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idemKey,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await res.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }
    return { ok: res.ok, status: res.status, data: parsed };
  } finally {
    clearTimeout(timer);
  }
}

// One account-wide singleton serializes outbound requests across visitors and
// Worker instances. Never retry automatically: unavailable stays unavailable.
async function clockedCall(env, path, payload, idemKey) {
  if (!env.CLOCKED_QUEUE) throw new Error('request queue unavailable');
  const stub = env.CLOCKED_QUEUE.get(env.CLOCKED_QUEUE.idFromName('clocked-account'));
  const response = await stub.fetch('https://queue.internal/call', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({path, payload, idemKey})
  });
  if (!response.ok) throw new Error('request queue unavailable');
  return response.json();
}

export class ClockedQueue {
  constructor(ctx, env) {
    this.env = env;
    this.tail = Promise.resolve();
    this.pending = 0;
  }
  async fetch(request) {
    const input = await request.json();
    if (!['/pii','/injection','/script','/grounding','/rerank'].includes(input.path)) {
      return new Response('invalid endpoint', {status:400});
    }
    if (this.pending >= 20) return new Response('queue full', {status:503});
    this.pending++;
    const job = this.tail.then(() => directClockedCall(this.env, input.path, input.payload, input.idemKey));
    this.tail = job.catch(() => {});
    try { return Response.json(await job); }
    catch { return new Response('upstream unavailable', {status:502}); }
    finally { this.pending--; }
  }
}

export default {
  async fetch(request, env) {
    const allowed = String(env.ALLOWED_ORIGIN || '*').split(',').map((s) => s.trim()).filter(Boolean);
    const reqOrigin = request.headers.get('Origin') || '';
    const origin = allowed.includes('*') ? '*' : (allowed.includes(reqOrigin) ? reqOrigin : allowed[0]);
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === '/api/health') {
      return json({ ok: true, service: 'promptshield' }, 200, origin);
    }

    if (!['/api/analyze', '/api/ground'].includes(url.pathname) || request.method !== 'POST') {
      return json({ error: 'not found' }, 404, origin);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rate = await rateCheck(env, ip);
    if (!rate.ok) {
      return json({ error: rate.reason }, rate.status, origin);
    }

    if (url.pathname === '/api/ground') {
      return handleGround(request, env, origin);
    }

    let input;
    try {
      input = await request.json();
    } catch {
      return json({ error: 'invalid JSON body' }, 400, origin);
    }

    const prompt = typeof input.prompt === 'string' ? input.prompt : '';
    const script = typeof input.script === 'string' ? input.script : '';
    if (!prompt.trim() && !script.trim()) {
      return json({ error: 'paste a prompt, a tool script, or both' }, 400, origin);
    }
    if (prompt.length > 20000 || script.length > 20000) {
      return json({ error: 'input too long (20,000 character limit each)' }, 400, origin);
    }

    // One idempotency key per endpoint call: Clocked scopes a key to its
    // first input account-wide, so each call needs its own UUID.
    const runId = crypto.randomUUID();
    const jobs = {};

    if (prompt.trim()) {
      jobs.protect = clockedCall(env, '/pii', { text: prompt }, crypto.randomUUID());
      jobs.guard = clockedCall(env, '/injection', { text: prompt }, crypto.randomUUID());
    }
    if (script.trim()) {
      jobs.inspect = clockedCall(env, '/script', { script }, crypto.randomUUID());
    }

    const names = Object.keys(jobs);
    const settled = await Promise.allSettled(names.map((n) => jobs[n]));

    const result = { id: runId };
    let anyFailure = false;
    names.forEach((name, i) => {
      const s = settled[i];
      if (s.status === 'fulfilled') {
        result[name] = s.value;
        if (!s.value.ok) anyFailure = true;
      } else {
        anyFailure = true;
        result[name] = {
          ok: false,
          status: 0,
          data: { error: s.reason && s.reason.name === 'AbortError' ? 'clocked api timeout' : String(s.reason) },
        };
      }
    });

    return json(result, anyFailure ? 502 : 200, origin);
  },
};

// Grounding layer: check the agent prompt's claims against a policy or source
// document the user supplies (Verify), and surface the passages that matter
// (Rerank). Every claim keeps its verdict visible: supported, contradicted,
// or not stated - evidence for a human to judge, not a guarantee.
async function handleGround(request, env, origin) {
  let input;
  try {
    input = await request.json();
  } catch {
    return json({ error: 'invalid JSON body' }, 400, origin);
  }
  const answer = typeof input.answer === 'string' ? input.answer : '';
  const policy = typeof input.policy === 'string' ? input.policy : '';
  if (!answer.trim() || !policy.trim()) {
    return json({ error: 'paste both a prompt or answer to check and a policy document' }, 400, origin);
  }
  if (answer.length > 20000 || policy.length > 20000) {
    return json({ error: 'input too long (20,000 character limit each)' }, 400, origin);
  }
  const passages = splitPassages(policy);
  if (passages.length === 0) {
    return json({ error: 'the policy document needs at least one passage of 20+ characters' }, 400, origin);
  }

  const jobs = {
    verify: clockedCall(env, '/grounding', { answer: answer.slice(0, 8000), documents: passages }, crypto.randomUUID()),
    rerank: clockedCall(env, '/rerank', { query: answer.slice(0, 2000), documents: passages }, crypto.randomUUID()),
  };
  const names = Object.keys(jobs);
  const settled = await Promise.allSettled(names.map((n) => jobs[n]));

  const result = { id: crypto.randomUUID(), passages };
  let anyFailure = false;
  names.forEach((name, i) => {
    const s = settled[i];
    if (s.status === 'fulfilled') {
      result[name] = s.value;
      if (!s.value.ok) anyFailure = true;
    } else {
      anyFailure = true;
      result[name] = { ok: false, status: 0, data: { error: String(s.reason) } };
    }
  });

  return json(result, anyFailure ? 502 : 200, origin);
}
