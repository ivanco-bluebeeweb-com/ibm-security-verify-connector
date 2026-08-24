# Pricing History — IBM Security Verify Connector

## Notes from this pricing run

- First `save_pricing` call used a wrong parameter key (`action_prices` instead
  of `tool_prices`) — the tool schema needed reloading via `load_app_tools` to
  confirm the correct key name.
- Second call used the correct key but referenced two action names that didn't
  match the actual deployed handler names (guessed `list_mfa_factors` /
  `remove_mfa_factor` instead of the real `list_user_mfa_factors` /
  `remove_user_mfa_factor`) — fixed by grepping `handlers.py` for the real
  `@chat.function` names before retrying.
- Third call (correct key + correct names) hit the now-familiar first-call
  silent-mismatch quirk (model stored as `'free'`, prices "not stored", no API
  error) — task #2467 tracks this platform bug. An identical retry succeeded.
- **Standing lesson for future apps**: always verify the exact tool_prices key
  name and the exact deployed action names (via `grep @chat.function` or the
  manifest) BEFORE calling save_pricing, then still expect to retry once for
  the known silent-failure quirk.

## Final pricing (per_action model)

| Action | Price (tokens) |
|---|---|
| connect_verify | 0 (free) |
| disconnect_verify | 0 (free) |
| list_connections | 0 (free) |
| get_group | 10 |
| get_policy | 10 |
| list_groups | 10 |
| list_policies | 10 |
| get_application | 15 |
| get_user | 15 |
| list_applications | 15 |
| list_user_mfa_factors | 15 |
| list_users | 15 |
| add_user_to_group | 20 |
| list_audit_events | 20 |
| remove_user_from_group | 20 |
| update_user | 20 |
| audit_tenant | 30 |
| create_group | 30 |
| create_user | 30 |
| delete_user | 30 |
| remove_user_mfa_factor | 30 |

Read/list operations priced lowest; user/group creation, permanent deletion
(SCIM hard-delete, unlike Okta's soft-delete), and MFA factor removal (a
lockout-recovery action with security implications) priced highest.
