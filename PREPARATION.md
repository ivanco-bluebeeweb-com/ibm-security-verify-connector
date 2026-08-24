# IBM Security Verify Connector — Preparation

**Version:** 0.1.0 (planning)
**Date:** 2026-08-24
**Related task:** BBW Imperal Apps (IAM/Access Management category — IBM Security Verify), task #2464
**Scope decision:** maximum feasible capability against the IBM Security Verify
SaaS management API (per standing "максимальный функционал" instruction).

## 1. App passport

**Name:** IBM Security Verify Connector
**One-line purpose:** Connect your own IBM Security Verify SaaS tenant to manage
Users and Groups (SCIM 2.0), Applications, Access Policies, and review Audit
Events for security visibility.

**What it is not:**
- Not IBM Security Verify Access (formerly ISAM) — the separate on-prem product
  with a completely different WGA/RTSS-based API. Out of scope for v1; a future
  connector if ever needed.
- Not IBM Security QRadar (already a separate Imperal app: IBM QRadar Connector)
  — no overlap, Verify is identity/access, QRadar is SIEM.

## 2. Human problem

> An IT admin or security engineer running IBM Security Verify (common in
> large banks/government on an IBM stack) needs to provision/deprovision a
> user, manage group membership, review an OIDC/SAML application, check an
> access policy, or investigate an audit event — without opening the Verify
> admin console for every routine task.

### Personas
| Persona | Trigger | Value |
|---|---|---|
| IT admin | New hire needs an account | create_user via SCIM |
| Security engineer | Reviewing recent auth events | list_audit_events filtered by type/date |
| Helpdesk agent | User locked out / needs MFA reset | list_user_mfa_factors, remove a factor |
| Tenant admin | Wants a tenant health snapshot | audit_tenant — disabled users, recent failed logins |

## 3. Release scope decision

Standing instruction: "максимальный функционал" — build the full feasible
Tier 1+2+3 in one pass, no re-asking.

## 4. Safety notes

- SCIM-based pagination/filtering differs from the rest of the portfolio
  (startIndex/count, SCIM filter grammar) — documented explicitly in
  CONNECTOR_DISCOVERY.md so handlers don't silently misbehave.
- Access Policies are risk-sensitive (can block sign-in) — write/edit excluded
  from v1, read-only only, same posture as Entra ID Conditional Access.
- On-prem ISAM/Verify Access explicitly out of scope — documented so future
  sessions don't conflate the two products under one connector.
