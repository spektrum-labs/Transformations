"""Schema for epp_transform transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EndpointHealth(BaseModel):
    """Health details for an endpoint."""

    services: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class AssignedProduct(BaseModel):
    """Product assigned to an endpoint."""

    code: Optional[str] = None
    status: Optional[str] = None

    class Config:
        extra = "allow"


class Endpoint(BaseModel):
    """An endpoint device from the EPP platform."""

    type: Optional[str] = None
    assignedProducts: Optional[List[AssignedProduct]] = None
    health: Optional[EndpointHealth] = None
    cloud: Optional[Dict[str, Any]] = None
    encryption: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class EppTransformInput(BaseModel):
    """
    Expected input schema for the epp_transform transformation.

    Evaluates endpoint protection coverage based on endpoints response data.
    Processes items array containing endpoint details with assigned products,
    health services, and device types.
    """

    isEPPConfigured: Optional[bool] = None
    items: Optional[List[Endpoint]] = None

    class Config:
        extra = "allow"
