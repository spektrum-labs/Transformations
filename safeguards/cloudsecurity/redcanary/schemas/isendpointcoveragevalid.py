"""Schema for isendpointcoveragevalid transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsendpointcoveragevalidInput(BaseModel):
    """
    Expected input schema for the isendpointcoveragevalid transformation.
    Criteria key: isEndpointCoverageValid

    Validates that endpoint coverage meets the required threshold
    by checking the endpoints endpoint for monitored endpoints.
    """

    endpoints: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
