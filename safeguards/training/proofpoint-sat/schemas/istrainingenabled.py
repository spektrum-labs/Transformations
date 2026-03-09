"""Schema for istrainingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IstrainingenabledInput(BaseModel):
    """
    Expected input schema for the istrainingenabled transformation.
    Criteria key: isTrainingEnabled

    Validates that security awareness training assignments exist in the
    Proofpoint SAT system (total_records > 0).
    """

    total_records: Optional[int] = Field(None, description="Total number of training assignment records")
    assignments: Optional[List[Dict[str, Any]]] = Field(None, description="List of training assignment objects")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Generic data wrapper for assignment records")

    class Config:
        extra = "allow"
