"""IBM Security Verify Connector -- center panels for Users/Groups/
Applications/Access Policies/Audit Events."""
from __future__ import annotations

from imperal_sdk import ui

import handlers as h
from app import ext


def _table_or_empty(rows, columns, empty_message, empty_icon):
    if not rows:
        return ui.Empty(message=empty_message, icon=empty_icon)
    return ui.DataTable(rows=rows, columns=columns)


@ext.panel("verify_users", slot="center", title="Users", center_overlay=True)
async def verify_users(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Users")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/v2.0/Users", params={"count": 50})
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load users: {exc}")
    items = (data or {}).get("Resources", [])
    rows = []
    for u in items:
        name = u.get("name", {}) or {}
        emails = u.get("emails", []) or []
        rows.append({
            "name": (name.get("givenName", "") + " " + name.get("familyName", "")).strip(),
            "username": u.get("userName", ""),
            "email": emails[0].get("value", "") if emails else "",
            "active": "Yes" if u.get("active", True) else "No",
        })
    columns = [
        ui.DataColumn(key="name", label="Name"),
        ui.DataColumn(key="username", label="Username"),
        ui.DataColumn(key="email", label="Email"),
        ui.DataColumn(key="active", label="Active"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Users", level=2),
        _table_or_empty(rows, columns, "No users found", "Users"),
    ])


@ext.panel("verify_groups", slot="center", title="Groups", center_overlay=True)
async def verify_groups(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="UsersRound")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/v2.0/Groups", params={"count": 50})
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load groups: {exc}")
    items = (data or {}).get("Resources", [])
    rows = [{
        "name": g.get("displayName", ""),
        "members": str(len(g.get("members", []) or [])),
    } for g in items]
    columns = [
        ui.DataColumn(key="name", label="Group name"),
        ui.DataColumn(key="members", label="Members"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Groups", level=2),
        _table_or_empty(rows, columns, "No groups found", "UsersRound"),
    ])


@ext.panel("verify_applications", slot="center", title="Applications", center_overlay=True)
async def verify_applications(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="AppWindow")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/v1.0/applications")
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load applications: {exc}")
    items = data if isinstance(data, list) else (data or {}).get("applications", [])
    rows = [{
        "name": a.get("name", "") or a.get("applicationName", ""),
        "type": a.get("type", "") or a.get("templateName", ""),
        "enabled": "Yes" if a.get("enabled", True) else "No",
    } for a in items]
    columns = [
        ui.DataColumn(key="name", label="Name"),
        ui.DataColumn(key="type", label="Type"),
        ui.DataColumn(key="enabled", label="Enabled"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Applications", level=2),
        _table_or_empty(rows, columns, "No applications found", "AppWindow"),
    ])


@ext.panel("verify_policies", slot="center", title="Access Policies", center_overlay=True)
async def verify_policies(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ShieldCheck")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/v1.0/policies")
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load policies: {exc}")
    items = data if isinstance(data, list) else (data or {}).get("policies", [])
    rows = [{
        "name": p.get("name", ""),
        "enabled": "Yes" if p.get("enabled", True) else "No",
    } for p in items]
    columns = [
        ui.DataColumn(key="name", label="Policy name"),
        ui.DataColumn(key="enabled", label="Enabled"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Access Policies", level=2),
        ui.Alert(type="info", message="Read-only in this connector -- create/edit policies in the IBM Security Verify admin console."),
        _table_or_empty(rows, columns, "No access policies found", "ShieldCheck"),
    ])


@ext.panel("verify_audit_events", slot="center", title="Audit Events", center_overlay=True)
async def verify_audit_events(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="History")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/v1.0/events", params={"limit": 50})
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load audit events: {exc}")
    items = data if isinstance(data, list) else (data or {}).get("events", [])
    rows = [{
        "type": e.get("eventType", "") or e.get("type", ""),
        "actor": e.get("actor", "") or e.get("initiatedBy", ""),
        "result": e.get("result", "") or e.get("outcome", ""),
        "recorded_at": e.get("timestamp", "") or e.get("recordedAt", ""),
    } for e in items]
    columns = [
        ui.DataColumn(key="type", label="Event type"),
        ui.DataColumn(key="actor", label="Actor"),
        ui.DataColumn(key="result", label="Result"),
        ui.DataColumn(key="recorded_at", label="Recorded at"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Audit Events", level=2),
        _table_or_empty(rows, columns, "No audit events found", "History"),
    ])
