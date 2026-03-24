"""Schema for defaultdenyinbound transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DefaultdenyinboundInput(BaseModel):
    """
    Expected input schema for the defaultdenyinbound transformation.
    Criteria key: defaultDenyInbound
    """

    rules: Optional[List[Dict]] = None

    class Config:
        extra = "allow"
