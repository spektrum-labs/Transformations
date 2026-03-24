"""Schema for isnetworksecurityloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsnetworksecurityloggingenabledInput(BaseModel):
    """
    Expected input schema for the isnetworksecurityloggingenabled transformation.
    Criteria key: isNetworkSecurityLoggingEnabled
    """

    servers: Optional[List[Dict]] = None

    class Config:
        extra = "allow"
