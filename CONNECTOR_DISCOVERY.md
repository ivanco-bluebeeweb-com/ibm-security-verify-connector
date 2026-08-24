# IBM Security Verify Connector — Connector Discovery

**Discovery date:** 2026-08-24
**Release scope:** maximum functionality against the IBM Security Verify SaaS
management API (per standing "максимальный функционал" instruction).
**Related task:** BBW Imperal Apps (IAM/Access Management category), task #2464.

## 1. What IBM Security Verify actually is

IBM Security Verify is IBM's cloud IDaaS (SaaS) platform — Gartner Leader in
Access Management, popular with large regulated enterprises already on the
IBM stack (banks, government). It exposes a REST management API at
`https://{tenant}.verify.ibm.com/v1.0/*` and `/v2.0/*`, split into logical
groups. It is a **separate product** from IBM Security Verify Access (the
on-prem, formerly-ISAM product) which has a completely different API
(WGA/RTSS-based) — out of scope for v1.

## 2. Chosen integration surface

**IBM Security Verify SaaS management API**:
- Users (`/v2.0/Users`) — SCIM 2.0-compliant: list, get, create, update,
  enable/disable, delete.
- Groups (`/v2.0/Groups`) — SCIM 2.0-compliant: list, get, create, membership
  add/remove.
- Applications (`/v1.0/applications`) — OIDC/SAML app registrations: list, get.
- Access Policies (`/v1.0/policies` under Access Management) — risk-based
  authentication policies: list, get only (read-only in v1, same posture as
  Entra ID Conditional Access — policies can lock out an org if misconfigured).
- MFA factors (`/v2.0/factors/{userId}` or equivalent per-user enrollment
  endpoint) — list enrolled factors, remove one (helpdesk lockout recovery).
- Audit Events (`/v1.0/events`) — audit trail: list, filtered by date/type.
- Reports — out of scope v1 (separate reporting surface, Tier 2/future).

## 3. Auth model

OAuth2 Client Credentials: an API Client is created in the Verify Admin
Console (Applications > On-Premises/API clients), yielding a `client_id` +
`client_secret`. Token endpoint: `https://{tenant}.verify.ibm.com/v1.0/endpoint/default/token`.
Standard client-credentials pattern already used across the portfolio
(Okta/Ping Identity/Entra ID) — reused deliberately, no new pattern invented.

## 4. SCIM difference (critical, must not be silently mishandled)

Users/Groups pagination and filtering follow the **SCIM 2.0 standard**, not
the offset/limit convention used by the rest of the connector portfolio:
- Pagination params: `startIndex` (1-based) and `count`, not `offset`/`limit`.
- Filtering: a SCIM filter expression string, e.g. `userName sw "jane"`, not a
  free-text `q` param.
This is modeled explicitly in schemas.py (`start_index`/`count` fields) and
in the client (`ibm_verify_client.py` builds the SCIM filter string), so it
is never accidentally treated like Okta/Ping/Entra's REST-style pagination.

## 5. Tiering

**Tier 1 (this release):** connect/disconnect/list_connections, audit_tenant,
Users CRUD via SCIM, Groups + membership via SCIM, Applications (read),
Access Policies (read), MFA factors (list/remove), Audit Events (list).

**Tier 2/future:** Access Policy write/edit (risk-sensitive, deliberately
excluded), Reports API, Adaptive Access risk engine configuration, on-prem
IBM Security Verify Access (ISAM) as a fully separate connector.
