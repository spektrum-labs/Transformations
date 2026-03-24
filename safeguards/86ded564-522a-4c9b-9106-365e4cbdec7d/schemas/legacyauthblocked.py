"""Schema for legacyauthblocked transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LegacyauthblockedInput(BaseModel):
    """
    Expected input schema for the legacyauthblocked transformation.
    Criteria key: legacyAuthBlocked
    """
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of Conditional Access policies")

    class Config:
        extra = "allow"
