# Target Scope

## Authorization

- Status: TODO - written authorization confirmed / pending.
- Authorization source: TODO - SRC program URL, email, contract, ticket, or internal approval ID.
- Window: TODO - YYYY-MM-DD HH:mm to YYYY-MM-DD HH:mm, timezone.
- Owner / SRC: TODO - organization and contact.
- Tester identity: TODO - account, team, or handle used for authorization.

## In Scope

- Target: TODO
- Domains:
  - TODO
- IP ranges:
  - TODO or N/A
- Apps / packages:
  - TODO or N/A
- Seed URLs:
  - TODO
- Allowed environments:
  - production read-only / staging / test tenant / other

## Out Of Scope

- Third-party domains unless explicitly listed above.
- Production destructive actions.
- Denial of service, stress testing, credential stuffing, social engineering.
- Bulk export of sensitive data.
- Payment, SMS, email, push notification, or irreversible workflows unless explicit test data is provided.
- Employee, customer, or private tenant data outside the approved test accounts.

## Test Accounts

- Anonymous / no-auth baseline:
- Low privilege:
- Peer user:
- Admin / high privilege:
- Test tenant / organization:

## Rate / Safety Limits

- Max threads:
- Max request rate:
- Allowed scanner templates:
- Disallowed scanner templates:

## Evidence Rules

- Redaction requirements:
- Maximum records to view:
- Screenshot allowed: yes/no
- Response body storage allowed: yes/no

## Notes

- Keep evidence minimal.
- Stop before irreversible state changes unless explicit test data is available.
