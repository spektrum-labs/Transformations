"""Schema for istrainingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IstrainingenabledInput(BaseModel):
    """
    Expected input schema for the istrainingenabled transformation.
    Criteria key: isTrainingEnabled

    Validates that security awareness training assignments are active
    by checking the assignments endpoint.
    """

    assignments: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
