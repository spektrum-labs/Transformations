"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class NetskopeAuditEvent(BaseModel):
    """Single audit event record from /api/v2/events/data/audit."""

    timestamp: Optional[int] = Field(
        default=None,
        description="Epoch timestamp of the audit event"
    )
    audit_log_event: Optional[str] = Field(
        default=None,
        description="Audit log event name (e.g., 'Login Successful', 'Edit Policy')"
    )
    user: Optional[str] = Field(
        default=None,
        description="User that triggered the audit event"
    )
    type: Optional[str] = Field(
        default=None,
        description="Audit event type (e.g., 'admin', 'nsadmin')"
    )
    organization_unit: Optional[str] = Field(
        default=None,
        description="Organization unit associated with the event"
    )
    ur_normalized: Optional[str] = Field(
        default=None,
        description="Normalized user identifier"
    )
    severity_level: Optional[Union[str, int]] = Field(
        default=None,
        description="Severity level of the audit event"
    )

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Validates active Netskope subscription via /api/v2/events/data/audit.
    Audit events are emitted on every active tenant regardless of which add-on
    modules are licensed, making this the most reliable license/tenant probe.
    """

    ok: Optional[Union[int, bool]] = Field(
        default=None,
        description="Netskope response status flag (1 = success)"
    )
    status: Optional[str] = Field(
        default=None,
        description="Response status string (e.g., 'success')"
    )
    result: Optional[List[NetskopeAuditEvent]] = Field(
        default=None,
        description="Array of audit event records returned by Netskope REST API v2"
    )
    data: Optional[List[NetskopeAuditEvent]] = Field(
        default=None,
        description="Alternate audit events array"
    )
    events: Optional[List[NetskopeAuditEvent]] = Field(
        default=None,
        description="Alternate audit events array"
    )
    items: Optional[List[NetskopeAuditEvent]] = Field(
        default=None,
        description="Alternate audit events array"
    )
    total: Optional[int] = Field(
        default=None,
        description="Total record count for the response"
    )
    total_count: Optional[int] = Field(
        default=None,
        description="Alternate total record count"
    )
    count: Optional[int] = Field(
        default=None,
        description="Count of records returned"
    )

    class Config:
        extra = "allow"
