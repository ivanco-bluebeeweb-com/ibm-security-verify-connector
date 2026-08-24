# IBM Security Verify Connector — UI Component Plan

Source: `UI_COMPONENT_VOCABULARY.md` + `~/UI_INTERFACE_STANDARD.md`. Only primitives
from the verified vocabulary are used below.

## Standing rules applied (binding for every screen in this plan)
- Every input carries its own visible label (via a `Text(variant="caption")` +
  input pair, never a bare placeholder).
- Placeholders are contextually specific to the exact field (e.g. a real-looking
  tenant hostname), never generic ("enter value").
- The connect form container is stretched to the full width of the left sidebar;
  its own contents (inputs, selects, buttons) stretch to fill it (`align="stretch"`).
- The sidebar carries NO instructions duplicated from the "How do I get this?"
  modal — the modal is the only place with the credential-setup walkthrough
  (API client entitlements + SaaS-vs-Verify-Access disambiguation).
- No `Card` (decorated box) anywhere in the left sidebar — plain `Stack` +
  `Divider` only.
- Secret fields use `ui.Password`, never `ui.Input(input_type="password")`.
- SCIM filter fields carry a placeholder showing the actual SCIM filter syntax
  (e.g. `userName sw "jane"`), never a generic "search" placeholder — this is
  a genuinely different input contract from the rest of the portfolio and must
  be visually distinct so users don't type free text that SCIM will reject.

## 1. Left sidebar (`slot="left"`)

**Not connected:**
- `Button` "How do I get this?" (ghost, opens `verify_connect_help` modal panel)
- `Form(action="connect_verify")`:
  - Tenant label `Input` (placeholder: "e.g. Acme Corp Verify")
  - Tenant hostname `Input` (placeholder: "mycompany.verify.ibm.com")
  - Client ID `Input` (placeholder: "API client ID")
  - Client Secret `Password` (placeholder: "API client secret")
  - Submit button "Connect"

**Connected (one or more tenants):**
- `Text` tenant label, `Divider`
- `Button` list (ghost, full width) opening each center panel:
  Users, Groups, Applications, Access Policies, MFA Factors, Audit Events
- `Divider`
- `Button` "App settings" (secondary, always last)

## 2. Center panels (`slot="center"`, `center_overlay=True`)

- `verify_users` — `ui.DataTable` (userName, display name, email, active) or
  `ui.Empty` if none. SCIM filter `Input` above the table with the syntax
  placeholder noted above.
- `verify_groups` — `ui.DataTable` (displayName, member count).
- `verify_applications` — `ui.DataTable` (name, type OIDC/SAML, enabled).
- `verify_access_policies` — `ui.DataTable` (name, type, enabled) — read-only,
  no edit/delete actions exposed anywhere in this panel (Tier 2 boundary).
- `verify_mfa_factors` — per-user factor list with a "Remove" `Button`
  (destructive variant) per row, gated behind a confirm step in the handler.
- `verify_audit_events` — `ui.DataTable` (event type, actor, target, result,
  timestamp), newest first.

## 3. Settings panel (`slot="center"`, via `__panel__verify_settings`)

- One row per connected tenant: label + hostname + "Disconnect" `Button`
  (destructive variant), calling `disconnect_verify` with that connection's id.

## 4. Explicit non-components (per vocabulary discipline)

No `Tabs`, no `Modal` other than the one connect-help modal, no nested
`Card`-in-`Card`. Every list panel follows the exact same
`Header` + `DataTable`-or-`Empty` shape used across Okta/Ping Identity/Entra ID
Connectors' center panels, for visual consistency across the IAM category.
