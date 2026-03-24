"""Schema for ismfarequiredforremoteaccess transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmfarequiredforremoteaccessInput(BaseModel):
    """
    Expected input schema for the ismfarequiredforremoteaccess transformation.
    Criteria key: isMFARequiredForRemoteAccess
    """
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of Conditional Access policies")

    class Config:
        extra = "allow"
