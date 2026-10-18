"""Schema for the Cisco Secure Access hasNetworkTunnelsConfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class HasNetworkTunnelsConfiguredInput(BaseModel):
    """
    GET /deployments/v2/networktunnelgroups envelope.
    Criteria key: hasNetworkTunnelsConfigured
    """

    data: Optional[List[Dict[str, Any]]] = None
    offset: Optional[int] = None
    limit: Optional[int] = None
    total: Optional[int] = None

    class Config:
        extra = "allow"
