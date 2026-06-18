# Target Scope

## Authorization

- Status: written authorization confirmed.
- Authorization source: https://src.example.com/program/example or internal ticket SEC-1234.
- Window: 2026-06-14 09:00 to 2026-06-21 18:00 Asia/Hong_Kong.
- Owner / SRC: Example SRC.
- Tester identity: your approved SRC account or team name.

## In Scope

- Target: example-src
- Domains:
  - example.com
  - app.example.com
  - api.example.com
- IP ranges:
  - N/A
  - 203.0.113.0/24 # example only; CLI guards enforce CIDR entries when present
- Apps / packages:
  - com.example.app
- Seed URLs:
  - https://www.example.com/
  - https://app.example.com/login
- Allowed environments:
  - production read-only
  - staging write tests allowed with test tenant only

## Out Of Scope

- Third-party analytics, captcha, payment, CDN, and customer support domains.
- DoS, stress testing, credential stuffing, social engineering.
- Bulk export of sensitive data.
- Irreversible state changes outside test tenant.

## Test Accounts

- Anonymous / no-auth baseline: no cookies.
- Low privilege: low@example.test
- Peer user: peer@example.test
- Admin / high privilege: only if explicitly approved.
- Test tenant / organization: Example-Test-Tenant.

## Rate / Safety Limits

- Max threads: 5
- Max request rate: 2 req/s
- Allowed wrappers: katana-crawl, ffuf-safe
- Disallowed scan types: brute force, destructive, DoS, intrusive fuzzing

## Evidence Rules

- Redaction requirements: redact tokens, phones, emails, IDs except minimal proof.
- Maximum records to view: 3.
- Screenshot allowed: yes, with redaction.
- Response body storage allowed: only sanitized excerpts.
