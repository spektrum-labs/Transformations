"""Schema for isintegrationsconnected transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IntegrationRecord(BaseModel):
    """A single integration entry from the SAFE integrations endpoint."""

    id: Optional[str] = Field(None, description="Integration identifier")
    name: Optional[str] = Field(None, description="Integration name (e.g. CrowdStrike)")
    status: Optional[str] = Field(None, description="Integration status (e.g. ACTIVE, connected)")
    syncStatus: Optional[str] = Field(None, description="Alternate sync status field")
    state: Optional[str] = Field(None, description="Alternate state field")

    class Config:
        extra = "allow"


class IsintegrationsconnectedInput(BaseModel):
    """Expected input schema for the isintegrationsconnected transformation. Criteria key: isIntegrationsConnected"""

    values: Optional[List[IntegrationRecord]] = Field(None, description="List of integration records")
    integrations: Optional[List[IntegrationRecord]] = Field(None, description="Alternate key for integration records")
    data: Optional[List[IntegrationRecord]] = Field(None, description="Alternate key for integration records")
    status: Optional[str] = Field(None, description="Status field when response is a single integration object")

    class Config:
        extra = "allow"
