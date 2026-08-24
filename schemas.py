"""Pydantic input contracts and SDL result entities for IBM Security Verify Connector."""
from __future__ import annotations

from imperal_sdk import sdl
from pydantic import BaseModel, Field


class NoParams(BaseModel):
    pass


class ConnectionRefParams(BaseModel):
    connection_id: str = Field("", description="Optional saved IBM Security Verify tenant connection ID. Omit to use the first connected tenant.")


class ConnectVerifyParams(BaseModel):
    label: str = Field("", description="Friendly tenant label, e.g. 'Acme Corp Verify'.")
    tenant_hostname: str = Field(..., description="Tenant hostname, e.g. 'mycompany.verify.ibm.com' (no https://).")
    client_id: str = Field(..., description="API Client's Client ID, from Applications > On-Premises/API clients.")
    client_secret: str = Field(..., description="API Client's Client Secret.")


class DisconnectVerifyParams(ConnectionRefParams):
    connection_id: str = Field(..., description="Saved IBM Security Verify tenant connection ID to remove from Imperal.")


class ListUsersParams(ConnectionRefParams):
    q: str = Field("", description="Optional SCIM filter fragment, e.g. 'userName sw \"jane\"'.")
    limit: int = Field(50, description="Max users to return (1-200).")


class UserIdParams(ConnectionRefParams):
    user_id: str = Field(..., description="IBM Security Verify SCIM user id.")


class CreateUserParams(ConnectionRefParams):
    user_name: str = Field(..., description="SCIM userName (usually the login/email).")
    given_name: str = Field(..., description="First name.")
    family_name: str = Field(..., description="Last name.")
    email: str = Field(..., description="Primary email address.")


class UpdateUserParams(UserIdParams):
    active: bool | None = Field(None, description="Set true to enable, false to disable sign-in. Omit to leave unchanged.")
    given_name: str = Field("", description="New first name, or leave blank to keep unchanged.")
    family_name: str = Field("", description="New last name, or leave blank to keep unchanged.")


class ListGroupsParams(ConnectionRefParams):
    q: str = Field("", description="Optional SCIM filter fragment, e.g. 'displayName sw \"Eng\"'.")
    limit: int = Field(50, description="Max groups to return (1-200).")


class GroupIdParams(ConnectionRefParams):
    group_id: str = Field(..., description="IBM Security Verify SCIM group id.")


class CreateGroupParams(ConnectionRefParams):
    display_name: str = Field(..., description="Group display name.")


class GroupMemberParams(ConnectionRefParams):
    group_id: str = Field(..., description="IBM Security Verify SCIM group id.")
    user_id: str = Field(..., description="IBM Security Verify SCIM user id to add/remove.")


class ListApplicationsParams(ConnectionRefParams):
    limit: int = Field(50, description="Max applications to return (1-200).")


class ApplicationIdParams(ConnectionRefParams):
    application_id: str = Field(..., description="IBM Security Verify application id.")


class ListPoliciesParams(ConnectionRefParams):
    limit: int = Field(50, description="Max access policies to return (1-200).")


class PolicyIdParams(ConnectionRefParams):
    policy_id: str = Field(..., description="IBM Security Verify access policy id.")


class ListMfaFactorsParams(ConnectionRefParams):
    user_id: str = Field(..., description="IBM Security Verify SCIM user id.")


class RemoveMfaFactorParams(ConnectionRefParams):
    user_id: str = Field(..., description="IBM Security Verify SCIM user id.")
    factor_id: str = Field(..., description="Enrolled MFA factor id to remove, from list_user_mfa_factors.")


class ListAuditEventsParams(ConnectionRefParams):
    event_type: str = Field("", description="Optional filter: only events of this type, e.g. 'authentication'.")
    limit: int = Field(50, description="Max audit events to return (1-200).")


# ---- SDL entities ----

class VerifyConnection(sdl.Entity):
    connection_id: str
    label: str
    tenant_hostname: str


class ConnectionList(sdl.Entity):
    connections: list[VerifyConnection]


class VerifyUser(sdl.Entity):
    user_id: str
    user_name: str
    given_name: str
    family_name: str
    email: str
    active: bool


class UserList(sdl.Entity):
    users: list[VerifyUser]


class VerifyGroup(sdl.Entity):
    group_id: str
    display_name: str
    member_count: int


class GroupList(sdl.Entity):
    groups: list[VerifyGroup]


class VerifyApplication(sdl.Entity):
    application_id: str
    name: str
    app_type: str
    enabled: bool


class ApplicationList(sdl.Entity):
    applications: list[VerifyApplication]


class VerifyPolicy(sdl.Entity):
    policy_id: str
    name: str
    enabled: bool


class PolicyList(sdl.Entity):
    policies: list[VerifyPolicy]


class VerifyMfaFactor(sdl.Entity):
    factor_id: str
    factor_type: str
    enrolled_at: str


class MfaFactorList(sdl.Entity):
    factors: list[VerifyMfaFactor]


class VerifyAuditEvent(sdl.Entity):
    event_id: str
    event_type: str
    actor: str
    result: str
    recorded_at: str


class AuditEventList(sdl.Entity):
    events: list[VerifyAuditEvent]


class DeleteResult(sdl.Entity):
    ok: bool
    detail: str


class HealthAudit(sdl.Entity):
    total_users: int
    disabled_users: int
    total_groups: int
    total_applications: int
    recent_failed_logins: int
    summary: str
