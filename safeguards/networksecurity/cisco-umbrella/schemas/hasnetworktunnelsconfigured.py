"""Schema for hasnetworktunnelsconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HasnetworktunnelsconfiguredInput(BaseModel):
    """
    Expected input schema for the hasnetworktunnelsconfigured transformation.
    Criteria key: hasNetworkTunnelsConfigured

    The tunnels endpoint returns a bare JSON array (empty when no site tunnels
    exist), so the transformation normalises both list and envelope shapes.
    """

    id: Optional[Any] = None
    name: Optional[str] = None
    state: Optional[str] = None
    siteOriginId: Optional[int] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
