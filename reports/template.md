# 漏洞标题

## 授权范围

- Target:
- Scope:
- Test time:

## 漏洞结论

- Type:
- Severity:
- Impact:

## 复现步骤

```bash
curl -i 'https://example.com/api/resource/1' \
  -H 'Cookie: ...'
```

## 证据

- Expected:
- Actual:
- Verified IDs / parameters:
- Accounts / roles compared:
- Normal flow source:

## 影响评估

- Confidentiality:
- Integrity:
- Availability:

## 误报排除

- Not CORS / security header / version disclosure / Self-XSS:
- Multiple-account or unauthenticated comparison:
- Cross-interface parameter migration attempted:
- Why this is not only a configuration observation:

## 修复建议

- Enforce object-level authorization on server side.
- Bind resource access to authenticated user / tenant / role.
- Add audit logs and regression tests for affected endpoints.

## 7 道验证门

- [ ] 有可复现 PoC / curl / 可执行命令。
- [ ] 报告的是实际安全影响，不是现象。
- [ ] 已验证多个 ID / 参数，或说明限制。
- [ ] 操作全部在授权范围内。
- [ ] 已排除 CORS / 安全头 / 版本号 / Self-XSS 等误报。
- [ ] 已尝试跨接口参数迁移，或说明不适用。
- [ ] 影响评估具体覆盖 C/I/A。
