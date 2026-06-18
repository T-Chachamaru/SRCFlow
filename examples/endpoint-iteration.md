# Endpoint Discovery Iteration Log

## Pre-Crawl Sampling Round

- Target:
- Config:
- Date/time:
- Scope file reviewed:
- Tool status checked:
- Browser pages exercised:
- Auth context:
- Katana routes collected:
- Katana scoped seed file:

### Network Observations

- API hosts:
- Domain keywords:
- Base paths:
- URL patterns:
- Static asset hosts:
- JS chunk patterns:
- Request wrappers:
- Dynamic path construction:
- Auth headers / cookie names:
- Query keys:
- Body keys:
- SPA routes to revisit:

### Config Changes

- `api_prefixes` added:
- `api_path_regexes` added:
- `extract_patterns` added:
- `known_endpoints` added:
- `garbage_substrings` added:

### Decision

- Config validated:
- Ready to crawl:
- Reason:

## Extraction Round

- Crawled files:
- Extracted endpoints before:
- Extracted endpoints after:
- Previous snapshot:
- Current snapshot:
- High-value files reviewed:
- HAR / Network source:
- Katana seed source:
- ffuf candidate source:
- Metrics summary:
- Flywheel note updated: yes/no

### Missed Patterns

- Miss source: Network / katana / JS review / HTML review / manifest / links / HAR
- Missed request wrapper:
- Missed path pattern:
- False-positive pattern:

### Results

- New endpoints:
- False positives:
- Files to reread:

### Next Round

- Continue / stop:
- Reason:
- Soft loop hint considered:
