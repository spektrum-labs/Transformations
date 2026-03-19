"""Schema for isauditplanactive transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuditAttributes(BaseModel):
    """Attributes of an audit."""
    title: Optional[str] = Field(None, description="Audit title")
    name: Optional[str] = Field(None, description="Alternate name field")
    slug: Optional[str] = Field(None, description="Audit slug identifier")
    status: Optional[str] = Field(None, description="Audit status (in progress, completed, planned)")
    state: Optional[str] = Field(None, description="Alternate status field")
    audit_status: Optional[str] = Field(None, description="Alternate audit status field")
    start_date: Optional[str] = Field(None, description="Audit start date")
    end_date: Optional[str] = Field(None, description="Audit end date")

    class Config:
        extra = "allow"


class AuditItem(BaseModel):
    """An audit from the ZenGRC audits API."""
    id: Optional[str] = Field(None, description="Audit ID")
    type: Optional[str] = Field(None, description="Resource type")
    attributes: Optional[AuditAttributes] = Field(None, description="Audit attributes (JSON:API format)")
    relationships: Optional[Any] = Field(None, description="Audit relationships")
    title: Optional[str] = Field(None, description="Audit title (flat format)")
    status: Optional[str] = Field(None, description="Audit status (flat format)")

    class Config:
        extra = "allow"


class IsauditplanactiveInput(BaseModel):
    """Expected input schema for the isauditplanactive transformation.
    Criteria key: isAuditPlanActive
    Source: ZenGRC GET /api/v2/audits"""
    data: Optional[List[AuditItem]] = Field(None, description="JSON:API data array of audits")
    audits: Optional[List[AuditItem]] = Field(None, description="Alternate audits list field")
    results: Optional[List[AuditItem]] = Field(None, description="Alternate results field")

    class Config:
        extra = "allow"
