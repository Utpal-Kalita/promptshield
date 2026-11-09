# PromptShield - Product Requirements

## Problem
People paste prompts, transcripts and tool scripts into AI agents without knowing what is inside them. A single paste can carry private data (PII), hidden prompt-injection instructions, or a script that does something harmful. And when an agent answers, nobody checks whether the answer is actually backed by the source policy it claims to follow.

## Solution
PromptShield is a pre-flight safety gate for agent prompts, plus a grounding layer for their claims. Paste a prompt (and optionally a tool script), and PromptShield shows what is risky before you run it. Paste the policy the prompt claims to follow, and PromptShield checks whether the claims hold up.

## Features
1. Protect (Clocked PII): finds personal data in the prompt and produces a masked copy that keeps the instructions but removes the private values.
2. Guard (Clocked injection): classifies prompt-injection patterns (instruction override, system-prompt theft, obfuscation, and more) with severity and the exact flagged lines.
3. Inspect (Clocked script risk): checks a pasted tool script for destructive, exfiltrating or evasive behavior before anyone runs it.
4. Verify (Clocked grounding): splits the prompt into claims and checks each against a pasted policy or source document (supported / contradicted / not stated), with the source passage shown for every verdict.
5. Rerank (Clocked rerank): ranks policy passages by relevance to the prompt so reviewers read the ones that matter.

## Users
Developers and operators who run AI agents on untrusted input: support transcripts, user-uploaded documents, community prompts, third-party scripts.

## Non-goals
- PromptShield is a safety signal, not a guarantee. Verdicts come from models and can be wrong; the UI says so and shows the evidence behind each verdict.
- It does not modify or execute the prompt or script. It only inspects.

## Architecture
- Frontend: static site (HTML/CSS/JS), currently on Cloudflare Pages, portable to Vercel.
- Backend: Cloudflare Worker proxying the Clocked API. Holds the API key as a secret (never in client code), enforces CORS to the frontend origin, and applies KV-backed rate limits (60 analyses/day global, 15/day per IP, fail-closed).
