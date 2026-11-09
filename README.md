# PromptShield

A pre-flight safety gate for AI agent prompts, plus a grounding layer for their claims. Built for the [Clocked Build Challenge](https://clocked.rezolve.ai/challenge) on the Clocked API.

**Live app:** https://promptshield-24r.pages.dev

## What it does

Paste an agent prompt (and optionally a tool script), and PromptShield shows what is inside before you run it:

- **Protect** (Clocked PII) finds personal data and produces a PII-masked copy. Masking removes private values only; it does not make a prompt safe.
- **Guard** (Clocked injection) classifies prompt-injection patterns with severity and quotes the flagged lines.
- **Inspect** (Clocked script risk) checks a pasted tool script for destructive, exfiltrating or evasive behavior.

Then paste the policy or source document the prompt claims to follow:

- **Verify** (Clocked grounding) splits the prompt into claims and checks each against the policy: supported / contradicted / not stated.
- **Rerank** (Clocked rerank) ranks policy passages by relevance so reviewers read the ones that matter.

## Honesty notes

- All verdicts and scores are model-reported and can be wrong. The UI labels them as such and never presents a model verdict as proof.
- A supported/contradicted verdict with no plausible matching policy passage is shown as unverified, not confirmed.
- The PII-masked prompt can still contain injections or risky instructions; masking removes personal data only.
- All demo fixtures are synthetic. No real personal data is used.

## Architecture

- `frontend/` - static site (HTML/CSS/JS), no build step. Hosted on Cloudflare Pages.
- `worker/` - Cloudflare Worker proxy for the Clocked API. The API key lives in a Worker secret, never in client code. CORS is locked to the frontend origin. KV-backed rate limits (60 analyses/day global, 15/day per IP) fail closed.
- `tests/regression.mjs` - live regression tests against the worker (supported / contradicted / absent / unrelated-claim cases plus Guard attack/benign). Each run spends a few Clocked credits.

## Run locally

Serve `frontend/` with any static server and point `API_BASE` in `frontend/app.js` at a deployed worker with a Clocked API key secret.

## Docs

- `prd.md` - product requirements
- `resources.md` - APIs, infrastructure and tools used
