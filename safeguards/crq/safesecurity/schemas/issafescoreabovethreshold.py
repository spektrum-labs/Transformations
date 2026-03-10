"""Schema for issafescoreabovethreshold transformation input."""
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field


class IssafescoreabovethresholdInput(BaseModel):
    """Expected input schema for the issafescoreabovethreshold transformation. Criteria key: isSAFEScoreAboveThreshold"""

    grade: Optional[str] = Field(None, description="Letter grade representing overall SAFE Score (e.g. A, B, C)")
    safeScore: Optional[str] = Field(None, description="Alternate field for the SAFE Score letter grade")
    score: Optional[str] = Field(None, description="Alternate field for the score value")
    scoreGrade: Optional[str] = Field(None, description="Alternate field for the score grade")
    breachLikelihood: Optional[Union[float, str]] = Field(None, description="Numeric breach likelihood as percentage or decimal")
    riskScore: Optional[Union[float, str]] = Field(None, description="Alternate numeric risk score field")
    likelihood: Optional[Union[float, str]] = Field(None, description="Alternate likelihood field")
    overallScore: Optional[Union[float, str]] = Field(None, description="Alternate overall score field")

    class Config:
        extra = "allow"
