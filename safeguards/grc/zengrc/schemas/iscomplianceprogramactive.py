"""Schema for iscomplianceprogramactive transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ProgramRelationships(BaseModel):
    """Relationships for a program."""
    owners: Optional[Any] = Field(None, description="Program owners relationship")
    primary_contact: Optional[Any] = Field(None, description="Primary contact relationship")

    class Config:
        extra = "allow"


class ProgramAttributes(BaseModel):
    """Attributes of a compliance program."""
    title: Optional[str] = Field(None, description="Program title")
    name: Optional[str] = Field(None, description="Alternate name field")
    slug: Optional[str] = Field(None, description="Program slug identifier")
    status: Optional[str] = Field(None, description="Program status (active, draft, effective)")
    state: Optional[str] = Field(None, description="Alternate status field")
    owner: Optional[str] = Field(None, description="Program owner")
    owners: Optional[Any] = Field(None, description="Program owners list")
    contact: Optional[str] = Field(None, description="Primary contact")
    primary_contact: Optional[str] = Field(None, description="Alternate contact field")

    class Config:
        extra = "allow"


class ProgramItem(BaseModel):
    """A compliance program from the ZenGRC programs API."""
    id: Optional[str] = Field(None, description="Program ID")
    type: Optional[str] = Field(None, description="Resource type")
    attributes: Optional[ProgramAttributes] = Field(None, description="Program attributes (JSON:API format)")
    relationships: Optional[ProgramRelationships] = Field(None, description="Program relationships")
    title: Optional[str] = Field(None, description="Program title (flat format)")
    status: Optional[str] = Field(None, description="Program status (flat format)")

    class Config:
        extra = "allow"


class IscomplianceprogramactiveInput(BaseModel):
    """Expected input schema for the iscomplianceprogramactive transformation.
    Criteria key: isComplianceProgramActive
    Source: ZenGRC GET /api/v2/programs"""
    data: Optional[List[ProgramItem]] = Field(None, description="JSON:API data array of programs")
    programs: Optional[List[ProgramItem]] = Field(None, description="Alternate programs list field")
    results: Optional[List[ProgramItem]] = Field(None, description="Alternate results field")

    class Config:
        extra = "allow"
