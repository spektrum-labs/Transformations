"""Schema for isriskscenarioconfigured transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RiskScenarioRecord(BaseModel):
    """A single risk scenario entry from the SAFE risk scenarios endpoint."""

    id: Optional[str] = Field(None, description="Scenario identifier")
    name: Optional[str] = Field(None, description="Scenario name (e.g. Ransomware)")
    status: Optional[str] = Field(None, description="Scenario status (e.g. ACTIVE, draft)")
    state: Optional[str] = Field(None, description="Alternate state field")

    class Config:
        extra = "allow"


class IsriskscenarioconfiguredInput(BaseModel):
    """Expected input schema for the isriskscenarioconfigured transformation. Criteria key: isRiskScenarioConfigured"""

    size: Optional[int] = Field(None, description="Total number of risk scenarios")
    totalCount: Optional[int] = Field(None, description="Alternate total count field")
    values: Optional[List[RiskScenarioRecord]] = Field(None, description="List of risk scenario records")
    riskScenarios: Optional[List[RiskScenarioRecord]] = Field(None, description="Alternate key for risk scenario records")
    scenarios: Optional[List[RiskScenarioRecord]] = Field(None, description="Alternate key for risk scenario records")
    data: Optional[List[RiskScenarioRecord]] = Field(None, description="Alternate key for risk scenario records")

    class Config:
        extra = "allow"
