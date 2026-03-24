"""Schema for isfirewallenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsfirerallenabledInput(BaseModel):
    """
    Expected input schema for the isfirewallenabled transformation.
    Criteria key: isFirewallEnabled
    """

    rules: Optional[List[Dict]] = None

    class Config:
        extra = "allow"
