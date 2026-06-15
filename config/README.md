# Config

`default.json` is the generic endpoint-discovery rule set and is not tied to any vendor or asset.

To create a target-specific config, copy or extend the default config:

```json
{
  "extends": "default.json",
  "target_keywords": ["example.com"],
  "extra_seeds": ["https://www.example.com/"],
  "api_prefixes": ["/api/", "/admin-api/"],
  "extract_patterns": [
    {
      "name": "CUSTOM_REQUEST_WRAPPER",
      "pattern": "request\\s*\\(\\s*\\{[^}]*url\\s*:\\s*[\"'`](?P<endpoint>/[^\"'`]+)[\"'`]",
      "kind": "relative",
      "confidence": "medium"
    }
  ]
}
```

`extract_patterns` must include the named group `(?P<endpoint>...)`.
