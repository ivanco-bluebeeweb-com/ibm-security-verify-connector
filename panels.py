"""IBM Security Verify Connector panels.

SIDEBAR CONTENT -- NO CARDS ANYWHERE, per ~/UI_INTERFACE_STANDARD.md's
"left sidebar, no decorated cards" rule (same convention as Microsoft Entra
ID Connector's / Ping Identity Connector's panels.py). Every section is a
plain ui.Stack, stacked vertically and left-aligned, no Card border/
background/shadow. Disconnect lives only in "App settings"
(panels_settings.py). The one secondary "App settings" button is always the
LAST element at the bottom of the sidebar.

Per Vlad's standing rule: every input carries its own label (not just a
placeholder), placeholders are contextually specific, the form container is
stretched to the full width of the left sidebar with its contents stretched
to fill it, and the sidebar carries NO instructions that duplicate the
"How do I set this up?" modal.
"""
from __future__ import annotations

from imperal_sdk import ui

import handlers as h
from app import ext


def _field(label: str, node: ui.UINode) -> ui.UINode:
    return ui.Stack(direction="v", gap=1, align="stretch", children=[
        ui.Text(label, variant="caption"),
        node,
    ])


def _settings_button() -> ui.UINode:
    return ui.Button(
        "App settings", variant="secondary", size="sm", full_width=True,
        icon="Settings", on_click=ui.Call("__panel__verify_settings"),
    )


@ext.panel("verify_sidebar", slot="left", title="IBM Security Verify")
async def verify_sidebar(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Stack(direction="v", gap=3, align="stretch", children=[
            ui.Button("How do I get this?", variant="ghost", size="sm", icon="HelpCircle",
                      on_click=ui.Call("__panel__verify_connect_help")),
            ui.Form(action="connect_verify", submit_label="Connect", children=[
                _field("Tenant label", ui.Input(param_name="label", placeholder="e.g. Acme Corp Verify")),
                _field("Tenant hostname", ui.Input(param_name="tenant_hostname", placeholder="mycompany.verify.ibm.com")),
                _field("Client ID", ui.Input(param_name="client_id", placeholder="API client ID")),
                _field("Client Secret", ui.Password(param_name="client_secret", placeholder="API client secret")),
            ]),
        ])
    buttons = [
        ("Users", "Users", "verify_users"),
        ("Groups", "UsersRound", "verify_groups"),
        ("Applications", "AppWindow", "verify_applications"),
        ("Access Policies", "ShieldCheck", "verify_policies"),
        ("Audit Events", "History", "verify_audit_events"),
    ]
    return ui.Stack(direction="v", gap=1, align="stretch", children=[
        *[ui.Button(label, variant="ghost", size="sm", icon=icon, full_width=True,
                    on_click=ui.Call(f"__panel__{panel}")) for label, icon, panel in buttons],
        ui.Divider(),
        _settings_button(),
    ])


@ext.panel("verify_connect_help", slot="center", title="How do I get this?", center_overlay=True)
async def verify_connect_help(ctx, **kwargs) -> ui.UINode:
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("This connects to the IBM Security Verify SaaS tenant (the cloud IDaaS product), not on-premises IBM Security Verify Access (formerly ISAM) — those use a different API.", variant="body"),
        ui.Text("1. In the Verify Admin Console, go to Applications > On-Premises/API clients > Add API client.", variant="body"),
        ui.Text("2. Grant entitlements: Manage users and groups, Read applications, Read policies, Read events.", variant="body"),
        ui.Text("3. Copy the Client ID and Client Secret shown after creation — the secret is shown only once.", variant="body"),
        ui.Text("4. Your tenant hostname is the part before '.verify.ibm.com' in your admin console URL, e.g. 'mycompany.verify.ibm.com'.", variant="body"),
    ])
