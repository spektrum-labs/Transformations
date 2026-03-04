"""Schema for isfirewallenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FirewallRule(BaseModel):
    """Single firewall rule from Zscaler ZIA."""

    state: Optional[str] = None
    status: Optional[str] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"


class IsfirewallenabledInput(BaseModel):
    """
    Expected input schema for the isfirewallenabled transformation.
    Criteria key: isFirewallEnabled

    Checks for cloud firewall rules and their enabled status
    in Zscaler ZIA.
    """

    firewallRules: Optional[List[FirewallRule]] = None
    responseData: Optional[List[Any]] = None
    firewallEnabled: Optional[bool] = None
    cloudFirewallEnabled: Optional[bool] = None

    class Config:
        extra = "allow"
