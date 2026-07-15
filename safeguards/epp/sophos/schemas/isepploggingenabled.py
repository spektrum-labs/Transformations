"""Schema for isepploggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SophosSiemRecord(BaseModel):
    """A single record from Sophos Central's SIEM feed (/siem/v1/events or
    /siem/v1/alerts).

    Field set derived from 521 live records across three production tenants
    (Spektrum Labs, 10370, Trebron) on 2026-07-15. Both feeds share one envelope
    but carry different keys - the event fields below are near-universal, while
    the alert-only fields appear on roughly 2% of records. Everything is therefore
    Optional: a missing field is normal, not a data problem.
    """

    # Present on 100% of records
    id: Optional[str] = Field(default=None, description="Unique record identifier")
    customer_id: Optional[str] = Field(default=None, description="Sophos tenant id the record belongs to")
    created_at: Optional[str] = Field(default=None, description="When Sophos recorded the event (ISO 8601)")
    when: Optional[str] = Field(default=None, description="When the event actually occurred (ISO 8601)")
    severity: Optional[str] = Field(default=None, description="Severity, e.g. 'low', 'medium', 'high'")
    type: Optional[str] = Field(default=None, description="Event type, e.g. 'Event::Endpoint::UpdateSuccess'")
    location: Optional[str] = Field(default=None, description="Hostname or location the record originated from")

    # Present on 95-99% of records
    source: Optional[str] = Field(default=None, description="Originating source of the record")
    endpoint_id: Optional[str] = Field(default=None, description="Endpoint the record relates to")
    endpoint_type: Optional[str] = Field(default=None, description="Endpoint type, e.g. 'computer', 'server'")
    source_info: Optional[Dict[str, Any]] = Field(default=None, description="Source detail, e.g. {'ip': '192.168.1.159'}")
    name: Optional[str] = Field(default=None, description="Human readable description of the record")
    group: Optional[str] = Field(default=None, description="Grouping, e.g. 'UPDATING', 'PROTECTION'")
    user_id: Optional[str] = Field(default=None, description="User associated with the record")

    # Alert-only fields (/siem/v1/alerts)
    product: Optional[str] = Field(default=None, description="Sophos product that raised the alert")
    category: Optional[str] = Field(default=None, description="Alert category")
    description: Optional[str] = Field(default=None, description="Alert description")
    actionable: Optional[bool] = Field(default=None, description="Whether the alert can be acted on via the API")
    allowedActions: Optional[List[Any]] = Field(default=None, description="Actions available for the alert")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Additional alert payload")
    javaUUID: Optional[str] = Field(default=None, description="Legacy Sophos identifier")
    event_service_event_id: Optional[str] = Field(default=None, description="Underlying event service id")

    class Config:
        extra = "allow"


class IsEppLoggingEnabledInput(BaseModel):
    """Expected input: the Sophos Central SIEM feed envelope.

    GET /siem/v1/events -> {"has_more": bool, "items": [...], "next_cursor": str}

    Note: Token-Service preprocessing may unwrap this to the bare `items` list
    before the transform runs, in which case the input is a list and this model
    does not apply. The transform handles both shapes and must not treat a
    validation miss as a compliance failure.
    """

    has_more: Optional[bool] = Field(default=None, description="Whether more records are available via next_cursor")
    items: Optional[List[SophosSiemRecord]] = Field(default=None, description="The records themselves; legitimately empty on a quiet tenant")
    next_cursor: Optional[str] = Field(default=None, description="Cursor for the next page")

    class Config:
        extra = "allow"
