"""Schema for isrdpprotected transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsrdpprotectedInput(BaseModel):
    """
    Expected input schema for the isrdpprotected transformation.
    Criteria key: isRDPProtected
    """
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of Conditional Access policies")

    class Config:
        extra = "allow"
