"""Schema for iscompletionrateacceptable transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscompletionrateacceptableInput(BaseModel):
    """
    Expected input schema for the iscompletionrateacceptable transformation.
    Criteria key: isCompletionRateAcceptable

    Validates that the training completion rate is at or above 80%
    in Proofpoint SAT.
    """

    completion_rate: Optional[float] = Field(None, description="Training completion rate as a percentage")
    total_assigned: Optional[int] = Field(None, description="Total number of users assigned training")
    total_completed: Optional[int] = Field(None, description="Total number of users who completed training")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Generic data wrapper for completion records")

    class Config:
        extra = "allow"
