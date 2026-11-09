# Resources

## APIs used (Clocked platform - https://clocked.rezolve.ai)
- Protect / PII detection - finds personal data spans in text.
- Guard / injection classification - classifies prompt-injection patterns with severity.
- Inspect / script risk - assesses pasted tool scripts for risky behavior.
- Verify / grounding - verdicts per claim against source documents (supported / contradicted / not stated).
- Rerank - ranks documents by relevance to a query (use / skip + relevance score).

## Infrastructure
- Cloudflare Workers (backend proxy, secrets, KV rate limiting)
- Cloudflare Pages (frontend hosting; Vercel-compatible static site)

## Development tools
- Built with AI assistance (ChatGPT, DeepSeek, Gemini for ideation; Claude for implementation)
- wrangler CLI for Cloudflare deployment

## Data
- All demo fixtures are synthetic. No real personal data is used anywhere in the app or examples.
