"""Schema for isfirewallloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsfirewallloggingenabledInput(BaseModel):
    """
    Expected input schema for the isfirewallloggingenabled transformation.
    Criteria key: isFirewallLoggingEnabled
    """

    servers: Optional[List[Dict]] = None

    class Config:
        extra = "allow"
