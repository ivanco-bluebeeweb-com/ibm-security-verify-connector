"""IBM Security Verify Connector extension declaration.

IBM Security Verify is IBM's cloud IDaaS SaaS platform, managed through a REST
API at https://{tenant}.verify.ibm.com/{v1.0,v2.0}/* (v2.0 for SCIM 2.0
Users/Groups, v1.0 for Applications/Policies/Events).
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "ibm-security-verify-connector",
    version="0.1.0",
    display_name="IBM Security Verify",
    description=(
        "Connect your own IBM Security Verify SaaS tenant to manage Users "
        "and Groups (SCIM 2.0), Applications, Access Policies, MFA factors, "
        "and review Audit Events for security visibility."
    ),
    icon="icon.svg",
    capabilities=["verify:read", "verify:write"],
    actions_explicit=True,
    system=False,
)

chat = ChatExtension(
    ext,
    tool_name="ibm_verify",
    description=(
        "IBM Security Verify Connector — manage Users, Groups, "
        "Applications, Access Policies (read-only), MFA factors, and Audit "
        "Events for an IBM Security Verify SaaS tenant."
    ),
)

ext.secret(
    "verify_connections",
    "JSON list of connected IBM Security Verify tenants and encrypted API client credentials. Managed only through connect_verify and disconnect_verify.",
    required=True,
    write_mode="both",
    max_bytes=65536,
    rotation_hint_days=90,
)(lambda: None)


@ext.health_check
async def health_check(ctx) -> dict:
    """Report whether at least one IBM Security Verify tenant connection is saved."""
    import json

    raw = await ctx.secrets.get("verify_connections")
    connections = []
    if raw:
        try:
            connections = json.loads(raw)
        except (TypeError, ValueError):
            connections = []
    return {"healthy": True, "connected": bool(connections), "connection_count": len(connections)}
