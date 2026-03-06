"""Schema for isdnspolicyconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdnspolicyconfiguredInput(BaseModel):
    """
    Expected input schema for the isdnspolicyconfigured transformation.
    Criteria key: isDNSPolicyConfigured

    Validates that DNS filtering policies are configured with
    appropriate category blocks.
    """

    policies: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
