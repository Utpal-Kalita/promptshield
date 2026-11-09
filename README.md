# PromptShield

A pre-send review gate for AI support replies. Built for the [Clocked Build Challenge](https://clocked.rezolve.ai/challenge) on the Clocked API.

**Live app:** https://promptshield-frontend-phi.vercel.app (mirror: https://promptshield-24r.pages.dev)

## What it does

A support agent drafted a reply to a customer. Before anyone sends it, PromptShield reviews the whole exchange in one pass and ends in a single recommendation: **READY TO SEND (a human confirms), HOLD FOR REVIEW, or BLOCK**. It never sends anything - a person always makes the final call.

You paste three things: the customer ticket, the AI's draft reply, and the policy the reply must follow. PromptShield then:

1. **Injection screen** (Clocked Guard) - checks the ticket for hidden instructions aimed at the agent and marks the flagged lines in place on the ticket. An injected ticket is held, not auto-blocked: the customer's real request is preserved and shown so a person can answer it.
2. **Private data** (Clocked Protect) - finds personal data in the ticket and produces a masked copy for logs, shown as a before/after view. Masking removes private values only; it does not make text safe.
3. **Policy grounding** (Clocked Verify + Rerank) - checks every claim in the draft against the policy, claim by claim, and surfaces the policy passages that matter. A claim the evidence cannot back is marked **unverified** and is never shown green, whatever the model verdict says.
4. **Script inspection** (Clocked Inspect) - runs only when the conversation actually carries a script or commands (fenced code blocks are picked up automatically). A malicious script blocks the reply.

Every endpoint's output changes the verdict or what is shown - no decorative calls.

## Honesty notes

- All verdicts and scores are model-reported and can be wrong. The UI labels them as such and never presents a model verdict as proof.
- If a check fails or is unreachable it is shown as **unavailable** and the review is held as incomplete. A failed check is never rendered as an attack and never as a pass.
- A supported/contradicted verdict with no plausible matching policy passage (word-overlap hint, not model evidence) is shown as unverified, not confirmed.
- "No findings" means nothing was flagged; it is not a guarantee of safety.
- Known limitation (conservative false holds): the passage hint is a literal word-overlap check, not semantic verification. Paraphrased claims ("send the lamp back" vs the policy's "does not need to return a damaged item") and compound sentences that Verify merges into one claim can be marked unverified even when a person can see the policy covers them. Unverified means "needs a human look", never "wrong" - the app chooses an honest HOLD over an unearned green.
- All demo fixtures are synthetic. No real personal data is used.

## Architecture

- `frontend/` - static site (HTML/CSS/JS), no build step. Deployed on Vercel (primary) and Cloudflare Pages (mirror).
- `worker/` - Cloudflare Worker proxy for the Clocked API. The API key lives in a Worker secret, never in client code. CORS is locked to the two frontend origins. KV-backed rate limits (60 analyses/day global, 15/day per IP) fail closed.
- `tests/regression.mjs` - live regression tests against the worker (supported / contradicted / absent / unrelated-claim cases plus Guard attack/benign). Each run spends a few Clocked credits.

## Run locally

Serve `frontend/` with any static server and point `API_BASE` in `frontend/app.js` at a deployed worker with a Clocked API key secret.

## Docs

- `prd.md` - product requirements
- `resources.md` - APIs, infrastructure and tools used
