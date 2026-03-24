"""Schema for isfirewallconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsfirewallconfiguredInput(BaseModel):
    """
    Expected input schema for the isfirewallconfigured transformation.
    Criteria key: isFirewallConfigured
    """

    rules: Optional[List[Dict]] = None

    class Config:
        extra = "allow"
