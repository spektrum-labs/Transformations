"""Schema for iscontrolmonitoringenabled transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ControlRelationships(BaseModel):
    """Relationships for a control."""
    objectives: Optional[Any] = Field(None, description="Mapped objectives/framework requirements")
    regulations: Optional[Any] = Field(None, description="Mapped regulations")
    standards: Optional[Any] = Field(None, description="Mapped standards")

    class Config:
        extra = "allow"


class ControlAttributes(BaseModel):
    """Attributes of a control."""
    title: Optional[str] = Field(None, description="Control title")
    name: Optional[str] = Field(None, description="Alternate name field")
    slug: Optional[str] = Field(None, description="Control slug identifier")
    status: Optional[str] = Field(None, description="Control status (active, effective, implemented)")
    state: Optional[str] = Field(None, description="Alternate status field")
    last_assessed_at: Optional[str] = Field(None, description="Last assessment timestamp")
    lastAssessedAt: Optional[str] = Field(None, description="Alternate last assessed field")
    verified_date: Optional[str] = Field(None, description="Last verification date")
    frequency: Optional[str] = Field(None, description="Assessment frequency")
    assessment_frequency: Optional[str] = Field(None, description="Alternate frequency field")
    verify_frequency: Optional[str] = Field(None, description="Verification frequency")

    class Config:
        extra = "allow"


class ControlItem(BaseModel):
    """A control from the ZenGRC controls API."""
    id: Optional[str] = Field(None, description="Control ID")
    type: Optional[str] = Field(None, description="Resource type")
    attributes: Optional[ControlAttributes] = Field(None, description="Control attributes (JSON:API format)")
    relationships: Optional[ControlRelationships] = Field(None, description="Control relationships")
    title: Optional[str] = Field(None, description="Control title (flat format)")
    status: Optional[str] = Field(None, description="Control status (flat format)")

    class Config:
        extra = "allow"


class IscontrolmonitoringenabledInput(BaseModel):
    """Expected input schema for the iscontrolmonitoringenabled transformation.
    Criteria key: isControlMonitoringEnabled
    Source: ZenGRC GET /api/v2/controls"""
    data: Optional[List[ControlItem]] = Field(None, description="JSON:API data array of controls")
    controls: Optional[List[ControlItem]] = Field(None, description="Alternate controls list field")
    results: Optional[List[ControlItem]] = Field(None, description="Alternate results field")

    class Config:
        extra = "allow"
