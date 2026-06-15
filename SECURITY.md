# Security Policy

This project is intended for authorized security testing only.

Do not commit:

- real target credentials
- cookies, tokens, or API keys
- raw HAR files containing sensitive headers
- production response bodies with personal or confidential data
- target crawl output under `targets/*/raw`
- finding evidence under `targets/*/findings`

Use `targets/<target>/scope.md` to document authorization, rate limits, evidence handling, and out-of-scope systems before running active tests.
