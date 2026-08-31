"""Chat functions for IBM Security Verify Connector (SaaS SCIM + management API)."""
from __future__ import annotations

import json
import uuid

from imperal_sdk import ActionResult

import ibm_verify_client as vc
from app import chat
from schemas import (
    ApplicationIdParams, ApplicationList, AuditEventList, ConnectVerifyParams,
    ConnectionList, ConnectionRefParams, CreateGroupParams, CreateUserParams,
    DeleteResult, DisconnectVerifyParams, GroupIdParams, GroupList,
    GroupMemberParams, HealthAudit, ListApplicationsParams,
    ListAuditEventsParams, ListGroupsParams, ListMfaFactorsParams,
    ListPoliciesParams, ListUsersParams, MfaFactorList, NoParams,
    PolicyIdParams, PolicyList, RemoveMfaFactorParams, UpdateUserParams,
    UserIdParams, UserList, VerifyApplication, VerifyConnection, VerifyGroup,
    VerifyMfaFactor, VerifyPolicy, VerifyUser,
)

_SECRET_NAME = "verify_connections"


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_SECRET_NAME)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, connections: list[dict]) -> None:
    await ctx.secrets.set(_SECRET_NAME, json.dumps(connections))


def _connection_entity(c: dict) -> VerifyConnection:
    return VerifyConnection(
        connection_id=c.get("id", ""),
        label=c.get("label") or c.get("tenant_hostname", ""),
        tenant_hostname=c.get("tenant_hostname", ""),
    )


async def _resolve_connection(ctx, connection_id: str) -> dict:
    connections = await _load_connections(ctx)
    if not connections:
        raise vc.VerifyError("No IBM Security Verify tenant connected yet. Call connect_verify first.")
    if connection_id:
        for c in connections:
            if c.get("id") == connection_id:
                return c
        raise vc.VerifyError(f"No saved IBM Security Verify connection with id '{connection_id}'.")
    return connections[0]


def _client_for(c: dict) -> vc.VerifyClient:
    return vc.VerifyClient(
        tenant_hostname=c.get("tenant_hostname", ""),
        client_id=c.get("client_id", ""),
        client_secret=c.get("client_secret", ""),
    )


@chat.function("connect_verify", "Connect your own IBM Security Verify SaaS tenant via an API Client (OAuth2 client credentials), after verifying connectivity.", action_type="write", chain_callable=True, data_model=VerifyConnection, event="ibm-security-verify-connector.connect_verify", effects=["verify.provider.connected"])
async def connect_verify(ctx, params: ConnectVerifyParams) -> ActionResult:
    """Connect your own IBM Security Verify SaaS tenant via an API Client, after verifying connectivity."""
    client = vc.VerifyClient(tenant_hostname=params.tenant_hostname, client_id=params.client_id, client_secret=params.client_secret)
    try:
        await client.verify_connection()
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    connections = await _load_connections(ctx)
    entry = {
        "id": str(uuid.uuid4()),
        "label": params.label or params.tenant_hostname,
        "tenant_hostname": client.tenant_hostname,
        "client_id": params.client_id,
        "client_secret": params.client_secret,
    }
    connections.append(entry)
    await _save_connections(ctx, connections)
    return ActionResult.success(data=_connection_entity(entry), message="Connected to IBM Security Verify.", summary="Verify connected.")


@chat.function("disconnect_verify", "Disconnect an IBM Security Verify tenant: deletes only the saved credentials. Nothing in Verify itself is changed.", action_type="write", chain_callable=True, data_model=DeleteResult, event="ibm-security-verify-connector.disconnect_verify", effects=["verify.provider.disconnected"])
async def disconnect_verify(ctx, params: DisconnectVerifyParams) -> ActionResult:
    """Disconnect an IBM Security Verify tenant: deletes only the saved credentials."""
    connections = await _load_connections(ctx)
    remaining = [c for c in connections if c.get("id") != params.connection_id]
    if len(remaining) == len(connections):
        return ActionResult.error(f"No saved IBM Security Verify connection with id '{params.connection_id}'.")
    await _save_connections(ctx, remaining)
    return ActionResult.success(data=DeleteResult(ok=True, detail=params.connection_id), message="Disconnected from IBM Security Verify.", summary="Verify disconnected.")


@chat.function("list_connections", "List the connected IBM Security Verify tenants.", action_type="read", chain_callable=True, data_model=ConnectionList, event="ibm-security-verify-connector.list_connections")
async def list_connections(ctx, params: NoParams) -> ActionResult:
    """List the connected IBM Security Verify tenants."""
    connections = await _load_connections(ctx)
    return ActionResult.success(data=ConnectionList(connections=[_connection_entity(c) for c in connections]), summary="Connections listed.")


def _user_entity(u: dict) -> VerifyUser:
    name = u.get("name", {}) or {}
    emails = u.get("emails", []) or []
    email = emails[0].get("value", "") if emails else ""
    return VerifyUser(
        user_id=u.get("id", ""),
        user_name=u.get("userName", ""),
        given_name=name.get("givenName", ""),
        family_name=name.get("familyName", ""),
        email=email,
        active=bool(u.get("active", True)),
    )


@chat.function("list_users", "List users in the connected IBM Security Verify tenant, optionally filtered by a SCIM filter string.", action_type="read", chain_callable=True, data_model=UserList, event="ibm-security-verify-connector.list_users")
async def list_users(ctx, params: ListUsersParams) -> ActionResult:
    """List users in the connected IBM Security Verify tenant, optionally filtered by a SCIM filter string."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    q: dict = {"count": max(1, min(params.limit, 200))}
    if params.q:
        q["filter"] = params.q
    try:
        data, _ = await client.request("GET", "/v2.0/Users", params=q)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    items = (data or {}).get("Resources", [])
    return ActionResult.success(data=UserList(users=[_user_entity(u) for u in items]), summary="Users listed.")


@chat.function("get_user", "Read one IBM Security Verify user in full by SCIM id.", action_type="read", chain_callable=True, data_model=VerifyUser, event="ibm-security-verify-connector.get_user")
async def get_user(ctx, params: UserIdParams) -> ActionResult:
    """Read one IBM Security Verify user in full by SCIM id."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        data, _ = await client.request("GET", f"/v2.0/Users/{params.user_id}")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=_user_entity(data or {}), summary="User retrieved.")


@chat.function("create_user", "Create a new IBM Security Verify user via SCIM.", action_type="write", chain_callable=True, data_model=VerifyUser, event="ibm-security-verify-connector.create_user")
async def create_user(ctx, params: CreateUserParams) -> ActionResult:
    """Create a new IBM Security Verify user via SCIM."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": params.user_name,
        "name": {"givenName": params.given_name, "familyName": params.family_name},
        "emails": [{"value": params.email, "primary": True}],
        "active": True,
    }
    try:
        data, _ = await client.request("POST", "/v2.0/Users", json_body=body)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=_user_entity(data or {}), message="User created.", summary="User created.")


@chat.function("update_user", "Update selected fields of an existing IBM Security Verify user (active state and/or name). Only given fields change.", action_type="write", chain_callable=True, data_model=VerifyUser, event="ibm-security-verify-connector.update_user")
async def update_user(ctx, params: UpdateUserParams) -> ActionResult:
    """Update selected fields of an existing IBM Security Verify user. Only given fields change."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    ops = []
    if params.active is not None:
        ops.append({"op": "replace", "path": "active", "value": params.active})
    if params.given_name or params.family_name:
        name_val: dict = {}
        if params.given_name:
            name_val["givenName"] = params.given_name
        if params.family_name:
            name_val["familyName"] = params.family_name
        ops.append({"op": "replace", "path": "name", "value": name_val})
    if not ops:
        return ActionResult.error("No fields given to update.")
    body = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": ops}
    try:
        data, _ = await client.request("PATCH", f"/v2.0/Users/{params.user_id}", json_body=body)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=_user_entity(data or {}), message="User updated.", summary="User updated.")


@chat.function("delete_user", "Permanently delete an IBM Security Verify user via SCIM. Cannot be undone -- unlike Okta's deactivate, this is a hard delete.", action_type="write", chain_callable=True, data_model=DeleteResult, event="ibm-security-verify-connector.delete_user")
async def delete_user(ctx, params: UserIdParams) -> ActionResult:
    """Permanently delete an IBM Security Verify user via SCIM. Cannot be undone."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        await client.request("DELETE", f"/v2.0/Users/{params.user_id}")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=DeleteResult(ok=True, detail=params.user_id), message="User permanently deleted.", summary="User deleted.")


def _group_entity(g: dict) -> VerifyGroup:
    members = g.get("members", []) or []
    return VerifyGroup(
        group_id=g.get("id", ""),
        display_name=g.get("displayName", ""),
        member_count=len(members),
    )


@chat.function("list_groups", "List groups in the connected IBM Security Verify tenant.", action_type="read", chain_callable=True, data_model=GroupList, event="ibm-security-verify-connector.list_groups")
async def list_groups(ctx, params: ListGroupsParams) -> ActionResult:
    """List groups in the connected IBM Security Verify tenant."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    q: dict = {"count": max(1, min(params.limit, 200))}
    if params.q:
        q["filter"] = params.q
    try:
        data, _ = await client.request("GET", "/v2.0/Groups", params=q)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    items = (data or {}).get("Resources", [])
    return ActionResult.success(data=GroupList(groups=[_group_entity(g) for g in items]), summary="Groups listed.")


@chat.function("get_group", "Read one IBM Security Verify group in full.", action_type="read", chain_callable=True, data_model=VerifyGroup, event="ibm-security-verify-connector.get_group")
async def get_group(ctx, params: GroupIdParams) -> ActionResult:
    """Read one IBM Security Verify group in full."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        data, _ = await client.request("GET", f"/v2.0/Groups/{params.group_id}")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=_group_entity(data or {}), summary="Group retrieved.")


@chat.function("create_group", "Create a new IBM Security Verify group.", action_type="write", chain_callable=True, data_model=VerifyGroup, event="ibm-security-verify-connector.create_group")
async def create_group(ctx, params: CreateGroupParams) -> ActionResult:
    """Create a new IBM Security Verify group."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": params.display_name,
    }
    try:
        data, _ = await client.request("POST", "/v2.0/Groups", json_body=body)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=_group_entity(data or {}), message="Group created.", summary="Group created.")


@chat.function("add_user_to_group", "Add a user to an IBM Security Verify group.", action_type="write", chain_callable=True, data_model=DeleteResult, event="ibm-security-verify-connector.add_user_to_group")
async def add_user_to_group(ctx, params: GroupMemberParams) -> ActionResult:
    """Add a user to an IBM Security Verify group."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": params.user_id}]}],
    }
    try:
        await client.request("PATCH", f"/v2.0/Groups/{params.group_id}", json_body=body)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=DeleteResult(ok=True, detail=params.user_id), message="User added to group.", summary="User to group created.")


@chat.function("remove_user_from_group", "Remove a user from an IBM Security Verify group.", action_type="write", chain_callable=True, data_model=DeleteResult, event="ibm-security-verify-connector.remove_user_from_group")
async def remove_user_from_group(ctx, params: GroupMemberParams) -> ActionResult:
    """Remove a user from an IBM Security Verify group."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "remove", "path": f'members[value eq "{params.user_id}"]'}],
    }
    try:
        await client.request("PATCH", f"/v2.0/Groups/{params.group_id}", json_body=body)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=DeleteResult(ok=True, detail=params.user_id), message="User removed from group.", summary="User from group deleted.")


def _application_entity(a: dict) -> VerifyApplication:
    return VerifyApplication(
        application_id=a.get("id", ""),
        name=a.get("name", "") or a.get("applicationName", ""),
        app_type=a.get("type", "") or a.get("templateName", ""),
        enabled=bool(a.get("enabled", True)),
    )


@chat.function("list_applications", "List OIDC/SAML application registrations in the connected IBM Security Verify tenant.", action_type="read", chain_callable=True, data_model=ApplicationList, event="ibm-security-verify-connector.list_applications")
async def list_applications(ctx, params: ListApplicationsParams) -> ActionResult:
    """List OIDC/SAML application registrations in the connected IBM Security Verify tenant."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        data, _ = await client.request("GET", "/v1.0/applications")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    items = data if isinstance(data, list) else (data or {}).get("applications", [])
    return ActionResult.success(data=ApplicationList(applications=[_application_entity(a) for a in items]), summary="Applications listed.")


@chat.function("get_application", "Read one IBM Security Verify application registration in full.", action_type="read", chain_callable=True, data_model=VerifyApplication, event="ibm-security-verify-connector.get_application")
async def get_application(ctx, params: ApplicationIdParams) -> ActionResult:
    """Read one IBM Security Verify application registration in full."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        data, _ = await client.request("GET", f"/v1.0/applications/{params.application_id}")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=_application_entity(data or {}), summary="Application retrieved.")


def _policy_entity(p: dict) -> VerifyPolicy:
    return VerifyPolicy(
        policy_id=p.get("id", ""),
        name=p.get("name", ""),
        enabled=bool(p.get("enabled", True)),
    )


@chat.function("list_policies", "List Access Policies (risk-based authentication policies) configured on the connected IBM Security Verify tenant (read-only).", action_type="read", chain_callable=True, data_model=PolicyList, event="ibm-security-verify-connector.list_policies")
async def list_policies(ctx, params: ListPoliciesParams) -> ActionResult:
    """List Access Policies configured on the connected IBM Security Verify tenant (read-only)."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        data, _ = await client.request("GET", "/v1.0/policies")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    items = data if isinstance(data, list) else (data or {}).get("policies", [])
    return ActionResult.success(data=PolicyList(policies=[_policy_entity(p) for p in items]), summary="Policies listed.")


@chat.function("get_policy", "Read one IBM Security Verify Access Policy in full (read-only).", action_type="read", chain_callable=True, data_model=VerifyPolicy, event="ibm-security-verify-connector.get_policy")
async def get_policy(ctx, params: PolicyIdParams) -> ActionResult:
    """Read one IBM Security Verify Access Policy in full (read-only)."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        data, _ = await client.request("GET", f"/v1.0/policies/{params.policy_id}")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=_policy_entity(data or {}), summary="Policy retrieved.")


def _mfa_entity(f: dict) -> VerifyMfaFactor:
    return VerifyMfaFactor(
        factor_id=f.get("id", ""),
        factor_type=f.get("type", ""),
        enrolled_at=f.get("created", "") or f.get("enrolledAt", ""),
    )


@chat.function("list_user_mfa_factors", "List MFA factors enrolled for an IBM Security Verify user.", action_type="read", chain_callable=True, data_model=MfaFactorList, event="ibm-security-verify-connector.list_user_mfa_factors")
async def list_user_mfa_factors(ctx, params: ListMfaFactorsParams) -> ActionResult:
    """List MFA factors enrolled for an IBM Security Verify user."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        data, _ = await client.request("GET", f"/v2.0/factors/{params.user_id}")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    items = data if isinstance(data, list) else (data or {}).get("factors", [])
    return ActionResult.success(data=MfaFactorList(factors=[_mfa_entity(f) for f in items]), summary="User mfa factors listed.")


@chat.function("remove_user_mfa_factor", "Remove one enrolled MFA factor from an IBM Security Verify user -- use when a user has lost their device and needs help re-enrolling.", action_type="write", chain_callable=True, data_model=DeleteResult, event="ibm-security-verify-connector.remove_user_mfa_factor")
async def remove_user_mfa_factor(ctx, params: RemoveMfaFactorParams) -> ActionResult:
    """Remove one enrolled MFA factor from an IBM Security Verify user."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    try:
        await client.request("DELETE", f"/v2.0/factors/{params.user_id}/{params.factor_id}")
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    return ActionResult.success(data=DeleteResult(ok=True, detail=params.factor_id), message="MFA factor removed. The user will need to re-enroll.", summary="User mfa factor deleted.")


def _audit_entity(e: dict) -> VerifyAuditEvent:
    return VerifyAuditEvent(
        event_id=e.get("id", "") or e.get("eventId", ""),
        event_type=e.get("eventType", "") or e.get("type", ""),
        actor=e.get("actor", "") or e.get("initiatedBy", ""),
        result=e.get("result", "") or e.get("outcome", ""),
        recorded_at=e.get("timestamp", "") or e.get("recordedAt", ""),
    )


@chat.function("list_audit_events", "List Audit Events (the audit trail of logins, admin actions, and policy evaluations) on the connected IBM Security Verify tenant.", action_type="read", chain_callable=True, data_model=AuditEventList, event="ibm-security-verify-connector.list_audit_events")
async def list_audit_events(ctx, params: ListAuditEventsParams) -> ActionResult:
    """List Audit Events on the connected IBM Security Verify tenant."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    q: dict = {"limit": max(1, min(params.limit, 200))}
    if params.event_type:
        q["eventType"] = params.event_type
    try:
        data, _ = await client.request("GET", "/v1.0/events", params=q)
    except vc.VerifyError as exc:
        return ActionResult.error(str(exc), retryable=exc.retryable)
    items = data if isinstance(data, list) else (data or {}).get("events", [])
    return ActionResult.success(data=AuditEventList(events=[_audit_entity(e) for e in items]), summary="Audit events listed.")


@chat.function("audit_tenant", "Build one aggregated health report for the connected IBM Security Verify tenant: total/disabled user counts, group/application counts, and recent failed logins.", action_type="read", chain_callable=True, data_model=HealthAudit, event="ibm-security-verify-connector.audit_tenant")
async def audit_tenant(ctx, params: ConnectionRefParams) -> ActionResult:
    """Build one aggregated health report for the connected IBM Security Verify tenant."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    total_users = disabled_users = total_groups = total_applications = recent_failed_logins = 0
    try:
        users_data, _ = await client.request("GET", "/v2.0/Users", params={"count": 200})
        users = (users_data or {}).get("Resources", [])
        total_users = (users_data or {}).get("totalResults", len(users))
        disabled_users = sum(1 for u in users if not u.get("active", True))
    except vc.VerifyError:
        pass
    try:
        groups_data, _ = await client.request("GET", "/v2.0/Groups", params={"count": 1})
        total_groups = (groups_data or {}).get("totalResults", 0)
    except vc.VerifyError:
        pass
    try:
        apps_data, _ = await client.request("GET", "/v1.0/applications")
        apps = apps_data if isinstance(apps_data, list) else (apps_data or {}).get("applications", [])
        total_applications = len(apps)
    except vc.VerifyError:
        pass
    try:
        events_data, _ = await client.request("GET", "/v1.0/events", params={"limit": 100, "result": "failure"})
        events = events_data if isinstance(events_data, list) else (events_data or {}).get("events", [])
        recent_failed_logins = len(events)
    except vc.VerifyError:
        pass
    return ActionResult.success(data=HealthAudit(
        total_users=total_users,
        disabled_users=disabled_users,
        total_groups=total_groups,
        total_applications=total_applications,
        recent_failed_logins=recent_failed_logins,
    ), summary="Tenant audit ready.")
