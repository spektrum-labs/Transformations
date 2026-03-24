"""Schema for conditionalaccesspoliciesactive transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConditionalaccesspoliciesactiveInput(BaseModel):
    """
    Expected input schema for the conditionalaccesspoliciesactive transformation.
    Criteria key: conditionalAccessPoliciesActive
    """
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of Conditional Access policies")

    class Config:
        extra = "allow"
