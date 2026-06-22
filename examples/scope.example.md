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
- Irreversible state changes outside test tenant.

## Test Accounts

- Anonymous / no-auth baseline: no cookies.
- Low privilege: auth.local.json profile: low.
- Peer user: auth.local.json profile: peer.
- Admin / high privilege: only if explicitly approved.
- Test tenant / organization: Example-Test-Tenant.

## Rate / Safety Limits

- Max threads: 5
- Max request rate: 2 req/s
- Allowed wrappers: ffuf-safe, gau-urls, katana-crawl, paramspider-urls
- Disallowed scan types: brute force, destructive, DoS, intrusive fuzzing

## Evidence Rules

- Evidence handling: user-managed evidence handling.
- Maximum records to view: 3.
- Screenshot allowed: yes.
- Response body storage allowed: yes, within authorization.
