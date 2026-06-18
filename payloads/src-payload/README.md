# SRC Payload Dictionary

Imported from `C:\Users\kiin\Desktop\src-payload`.

This cleaned collection contains 281 files, about 25 MB. It was imported from the larger local source, then pruned by removing duplicate dictionaries, removing broad account/password brute-force corpora, and capping oversized routine fuzz lists. It is organized by testing purpose so the agent can choose small, relevant wordlists during the soft loop instead of guessing paths or using broad payload sets.

## Use Rules

- Stay inside `targets/<target>/scope.md`.
- Treat every payload file as a lead generator, never as a finding.
- Use `ffuf-safe` only for a concrete scoped question: sibling path, parameter name, header name, body key/value, file path, or narrow injection probe.
- Prefer the smallest relevant dictionary first. The broad password/user corpora have been removed; still avoid auth, upload bombs, web shells, EICAR, and destructive payloads unless the scope explicitly permits that test in an isolated environment.
- After any fuzz run, review `targets/<target>/state/ffuf_candidates.json` and manually verify candidates through `log-test`.

## Directory Map

| Directory | Files | Purpose |
| --- | ---: | --- |
| `fuzzing/api-paths/` | 17 | API route, action, object, and documentation endpoint discovery. Best first choice for `ffuf-safe` path fuzzing; large corpus files are capped for routine use. |
| `fuzzing/params/` | 4 | Query parameter names, debug parameters, common method names, and body/header key discovery; broad lists are capped for routine use. |
| `fuzzing/files/` | 5 | JS/PHP/common file name discovery and path traversal candidate strings; broad JS/PHP lists are capped for routine use. |
| `fuzzing/lfi-file-read/` | 9 | LFI/file-read path dictionaries for Linux and Windows. Use only when file-read behavior is already suspected. |
| `fuzzing/payment-values/` | 12 | Business-logic amount values such as zero, one, ten, hundred, and boundary prices. Use only with test orders or explicitly approved payment flows. |
| `fuzzing/generic/` | 18 | Generic metacharacters, encodings, separators, JSON fuzz strings, format strings, and broad mutation lists. |
| `injection/sqli/` | 37 | SQL injection detection, blind SQLi, DB-specific payloads, auth bypass strings, and DB enumeration references. |
| `injection/ldap/` | 1 | LDAP injection fuzz strings. |
| `injection/ssrf/` | 8 | SSRF URL forms, host fuzzing, absolute URL variants, and CORS-related SSRF probes. |
| `injection/xss/` | 22 | XSS payload lists plus SVG/GIF/SWF/DOCX/XLSX metadata samples. |
| `injection/xxe/` | 27 | XXE payloads, local DTD references, XMP samples, and document-based XXE tooling references. |
| `auth/usernames/` | 9 | Small username lists, pinyin/name formats, SSH usernames, and common names. Broad account corpora were removed. |
| `auth/passwords/` | 26 | Small weak-password and default-credential lists. Large brute-force corpora such as rockyou-style lists were removed; do not use for credential stuffing. |
| `auth/jwt/` | 1 | JWT secret candidates. Only use against tokens/accounts you are authorized to test. |
| `auth/phones/` | 4 | Phone number dictionaries. Use only for authorized test data or format inference. |
| `upload/` | 45 | File upload bypass strings, malicious image samples, zip-slip archives, zip/png bombs, CSV injection, and shell examples. High risk; not for routine fuzz. |
| `references/payloader-payload-collection/` | 35 | A payload reference web application/project. Use as reading/reference material, not as a direct `ffuf-safe` wordlist source. |

## ffuf-safe Selection Guide

Path or API sibling discovery:

```powershell
python ai_src.py ffuf-safe <target> https://host/api/FUZZ .\payloads\src-payload\fuzzing\api-paths\api路径\API字典.txt --profile paths -- -fc 404 -ac
```

Parameter name discovery:

```powershell
python ai_src.py ffuf-safe <target> "https://host/api/search?FUZZ=test" .\payloads\src-payload\fuzzing\params\参数字典\web参数字典.txt --profile params -- -fc 404 -ac
```

Header or body key discovery:

```powershell
python ai_src.py ffuf-safe <target> https://host/api/action .\payloads\src-payload\fuzzing\params\参数字典\CommonDebugParamNames.txt --header "X-Debug-FUZZ: 1" --profile params -- -ac
python ai_src.py ffuf-safe <target> https://host/api/action .\payloads\src-payload\fuzzing\params\参数字典\web参数字典.txt --method POST --data '{"FUZZ":"test"}' --profile params -- -ac
```

File-read or LFI confirmation, only after a file-read primitive is suspected:

```powershell
python ai_src.py ffuf-safe <target> "https://host/download?file=FUZZ" .\payloads\src-payload\fuzzing\lfi-file-read\文件下载字典\LFI-Jhaddix.txt --profile paths -- -fc 404 -ac
```

Payment/business amount boundary testing, only with approved test data:

```powershell
python ai_src.py ffuf-safe <target> https://host/api/order .\payloads\src-payload\fuzzing\payment-values\支付漏洞字典\all.txt --method POST --data '{"amount":"FUZZ","itemId":"TEST"}' --profile params -- -ac
```

## Agent Loop Integration

When the loop reaches endpoint testing and a small fuzzing question exists:

1. Read this README and select one narrow dictionary category.
2. Prefer `fuzzing/api-paths`, `fuzzing/params`, or `fuzzing/files` for routine `ffuf-safe` work.
3. Use injection-specific payloads only after endpoint behavior suggests that class.
4. Avoid `auth/passwords` and `upload` unless the scope explicitly authorizes that exact test.
5. Keep rate low, review candidates manually, and record verified results with `log-test`.
