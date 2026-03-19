"""Schema for isriskassessmentcurrent transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class RiskRelationships(BaseModel):
    """Relationships for a risk."""
    owners: Optional[Any] = Field(None, description="Risk owners relationship")
    contacts: Optional[Any] = Field(None, description="Risk contacts relationship")

    class Config:
        extra = "allow"


class RiskAttributes(BaseModel):
    """Attributes of a risk."""
    title: Optional[str] = Field(None, description="Risk title")
    name: Optional[str] = Field(None, description="Alternate name field")
    risk_score: Optional[Union[int, float, str]] = Field(None, description="Risk score")
    riskScore: Optional[Union[int, float, str]] = Field(None, description="Alternate risk score field")
    score: Optional[Union[int, float, str]] = Field(None, description="Alternate score field")
    inherent_risk: Optional[Union[int, float, str]] = Field(None, description="Inherent risk score")
    risk_level: Optional[str] = Field(None, description="Risk level (critical, high, medium, low)")
    riskLevel: Optional[str] = Field(None, description="Alternate risk level field")
    severity: Optional[str] = Field(None, description="Risk severity")
    rating: Optional[str] = Field(None, description="Risk rating")
    category: Optional[str] = Field(None, description="Risk category")
    risk_category: Optional[str] = Field(None, description="Alternate category field")
    riskCategory: Optional[str] = Field(None, description="Alternate category field")
    owner: Optional[str] = Field(None, description="Risk owner")
    assigned_to: Optional[str] = Field(None, description="Assigned person")

    class Config:
        extra = "allow"


class RiskItem(BaseModel):
    """A risk from the ZenGRC risks API."""
    id: Optional[str] = Field(None, description="Risk ID")
    type: Optional[str] = Field(None, description="Resource type")
    attributes: Optional[RiskAttributes] = Field(None, description="Risk attributes (JSON:API format)")
    relationships: Optional[RiskRelationships] = Field(None, description="Risk relationships")
    title: Optional[str] = Field(None, description="Risk title (flat format)")
    risk_score: Optional[Union[int, float, str]] = Field(None, description="Risk score (flat format)")

    class Config:
        extra = "allow"


class IsriskassessmentcurrentInput(BaseModel):
    """Expected input schema for the isriskassessmentcurrent transformation.
    Criteria key: isRiskAssessmentCurrent
    Source: ZenGRC GET /api/v2/risks"""
    data: Optional[List[RiskItem]] = Field(None, description="JSON:API data array of risks")
    risks: Optional[List[RiskItem]] = Field(None, description="Alternate risks list field")
    results: Optional[List[RiskItem]] = Field(None, description="Alternate results field")

    class Config:
        extra = "allow"
