"""Schema for isnetworksecurityenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsnetworksecurityenabledInput(BaseModel):
    """
    Expected input schema for the isnetworksecurityenabled transformation.
    Criteria key: isNetworkSecurityEnabled
    """

    mode: Optional[str] = None

    class Config:
        extra = "allow"
