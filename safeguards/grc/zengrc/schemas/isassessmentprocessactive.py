"""Schema for isassessmentprocessactive transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AssessmentAttributes(BaseModel):
    """Attributes of an assessment."""
    title: Optional[str] = Field(None, description="Assessment title")
    name: Optional[str] = Field(None, description="Alternate name field")
    slug: Optional[str] = Field(None, description="Assessment slug identifier")
    status: Optional[str] = Field(None, description="Assessment status (active, completed, in progress)")
    state: Optional[str] = Field(None, description="Alternate status field")
    assessment_status: Optional[str] = Field(None, description="Alternate assessment status field")
    assessment_type: Optional[str] = Field(None, description="Type of assessment (vendor, control, etc.)")
    assessmentType: Optional[str] = Field(None, description="Alternate type field")

    class Config:
        extra = "allow"


class AssessmentRelationships(BaseModel):
    """Relationships for an assessment."""
    assessment_questions: Optional[Any] = Field(None, description="Assessment questions/criteria")
    questions: Optional[Any] = Field(None, description="Alternate questions field")
    criteria: Optional[Any] = Field(None, description="Assessment criteria")

    class Config:
        extra = "allow"


class AssessmentItem(BaseModel):
    """An assessment from the ZenGRC assessments API."""
    id: Optional[str] = Field(None, description="Assessment ID")
    type: Optional[str] = Field(None, description="Resource type")
    attributes: Optional[AssessmentAttributes] = Field(None, description="Assessment attributes (JSON:API format)")
    relationships: Optional[AssessmentRelationships] = Field(None, description="Assessment relationships")
    title: Optional[str] = Field(None, description="Assessment title (flat format)")
    status: Optional[str] = Field(None, description="Assessment status (flat format)")

    class Config:
        extra = "allow"


class IsassessmentprocessactiveInput(BaseModel):
    """Expected input schema for the isassessmentprocessactive transformation.
    Criteria key: isAssessmentProcessActive
    Source: ZenGRC GET /api/v2/assessments"""
    data: Optional[List[AssessmentItem]] = Field(None, description="JSON:API data array of assessments")
    assessments: Optional[List[AssessmentItem]] = Field(None, description="Alternate assessments list field")
    results: Optional[List[AssessmentItem]] = Field(None, description="Alternate results field")

    class Config:
        extra = "allow"
