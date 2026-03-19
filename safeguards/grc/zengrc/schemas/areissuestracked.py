"""Schema for areissuestracked transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IssueAttributes(BaseModel):
    """Attributes of an issue."""
    title: Optional[str] = Field(None, description="Issue title")
    name: Optional[str] = Field(None, description="Alternate name field")
    status: Optional[str] = Field(None, description="Issue status (open, closed, remediated)")
    state: Optional[str] = Field(None, description="Alternate status field")
    issue_status: Optional[str] = Field(None, description="Alternate issue status field")
    owner: Optional[str] = Field(None, description="Issue owner")
    assigned_to: Optional[str] = Field(None, description="Assigned person")
    due_on: Optional[str] = Field(None, description="Due date")
    dueOn: Optional[str] = Field(None, description="Alternate due date field")
    due_date: Optional[str] = Field(None, description="Alternate due date field")
    dueDate: Optional[str] = Field(None, description="Alternate due date field")
    end_date: Optional[str] = Field(None, description="Alternate end date field")

    class Config:
        extra = "allow"


class IssueRelationships(BaseModel):
    """Relationships for an issue."""
    owners: Optional[Any] = Field(None, description="Issue owners relationship")
    contacts: Optional[Any] = Field(None, description="Issue contacts relationship")

    class Config:
        extra = "allow"


class IssueItem(BaseModel):
    """An issue from the ZenGRC issues API."""
    id: Optional[str] = Field(None, description="Issue ID")
    type: Optional[str] = Field(None, description="Resource type")
    attributes: Optional[IssueAttributes] = Field(None, description="Issue attributes (JSON:API format)")
    relationships: Optional[IssueRelationships] = Field(None, description="Issue relationships")
    title: Optional[str] = Field(None, description="Issue title (flat format)")
    status: Optional[str] = Field(None, description="Issue status (flat format)")

    class Config:
        extra = "allow"


class AreissuestrackedInput(BaseModel):
    """Expected input schema for the areissuestracked transformation.
    Criteria key: areIssuesTracked
    Source: ZenGRC GET /api/v2/issues"""
    data: Optional[List[IssueItem]] = Field(None, description="JSON:API data array of issues")
    issues: Optional[List[IssueItem]] = Field(None, description="Alternate issues list field")
    results: Optional[List[IssueItem]] = Field(None, description="Alternate results field")

    class Config:
        extra = "allow"
