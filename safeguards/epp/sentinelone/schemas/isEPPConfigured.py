"""Schema for isEPPConfigured transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class HealthCheckData(BaseModel):
    """System health data returned by /system/status endpoint."""
    health: Optional[str] = Field(None, description="System health state, e.g. ok, error, degraded")
    status: Optional[str] = Field(None, description="System status string")
    id: Optional[str] = Field(None, description="Status record identifier")
    createdAt: Optional[str] = Field(None, description="Status record creation timestamp")

    class Config:
        extra = "allow"


class IsEPPConfiguredInput(BaseModel):
    """Expected input shape for the isEPPConfigured transformation."""
    data: Optional[Union[HealthCheckData, Dict[str, Any]]] = Field(None, description="Health check data object")
    healthCheck: Optional[Dict[str, Any]] = Field(None, description="Merged method result from healthCheck")

    class Config:
        extra = "allow"
