# PromptShield - Product Requirements

## Problem
Support teams are starting to let AI agents draft replies to customers. Before a reply goes out, someone should check three things: is the customer's ticket trying to steer the agent (prompt injection), does the conversation carry private data or a script nobody has read, and is the draft actually backed by the company policy it claims to follow. Today that check is a skim, if it happens at all.

## Solution
PromptShield is a pre-send review gate for AI support replies. You paste the customer ticket, the AI's draft reply, and the policy the reply must follow. One click runs four checks and ends in a single recommendation: READY TO SEND (a human confirms), HOLD FOR REVIEW, or BLOCK. PromptShield never sends anything; a person always makes the final call.

## Features
1. Injection screen (Clocked Guard): checks the ticket for hidden instructions aimed at the agent and marks the flagged lines in place on the ticket. An injected ticket is held, not auto-blocked: the customer's real request is preserved so a person can still answer it.
2. Private data (Clocked Protect): finds personal data in the ticket and produces a masked copy for logs, shown as a before/after view. Masking removes private values only.
3. Policy grounding (Clocked Verify + Rerank): checks every claim in the draft against the policy, claim by claim, and surfaces the passages that matter. A claim the evidence cannot back is marked unverified and never shown green, whatever the model verdict says.
4. Script inspection (Clocked Inspect): runs only when the conversation actually carries a script or commands (fenced code blocks are picked up automatically). A malicious script blocks the reply.

## Users
Support team leads and reviewers who approve AI-drafted replies before they reach customers.

## Non-goals
- PromptShield is a recommendation with evidence, not an authorization and not a guarantee. Verdicts come from models and can be wrong; the UI says so.
- It does not send, edit or delete anything, and it has no helpdesk integration.
- It does not modify or execute scripts. It only inspects.

## Failure behavior
If a check fails or is unreachable it is shown as unavailable and the review is held as incomplete. A failed check is never rendered as an attack and never as a pass.

## Known limitations
The passage hint behind "unverified" is a literal word-overlap check, not semantic verification. Paraphrases and compound sentences can produce conservative false holds. Unverified means "needs a human look", never "wrong".

## Architecture
- Frontend: static site (HTML/CSS/JS) on Vercel (primary) and Cloudflare Pages (mirror).
- Backend: Cloudflare Worker proxying the Clocked API. Holds the API key as a secret (never in client code), enforces CORS to the frontend origins, and applies KV-backed rate limits (60 analyses/day global, 15/day per IP, fail-closed).
