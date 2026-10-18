"""Schema for legacyauthblocked transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LegacyauthblockedInput(BaseModel):
    """
    Expected input schema for the legacyauthblocked transformation.
    Criteria key: legacyAuthBlocked
    """
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of Conditional Access policies")
    securityDefaults: Optional[Dict[str, Any]] = Field(
        None, description="GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy, merged in by the workflow")

    class Config:
        extra = "allow"
