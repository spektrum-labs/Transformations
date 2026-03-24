"""Schema for isemailfilteringenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsemailfilteringenabledInput(BaseModel):
    """
    Expected input schema for the isemailfilteringenabled transformation.
    Criteria key: isEmailFilteringEnabled
    """

    policies: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
