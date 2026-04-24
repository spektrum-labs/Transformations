"""Schema for confirmLicensePurchased transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class QueryDevicesResult(BaseModel):
    """Shape returned by the queryDevices method."""
    resources: Optional[List[Any]] = Field(default=None, description="List of device IDs returned by the Falcon Hosts query API")
    meta: Optional[Dict[str, Any]] = Field(default=None, description="Pagination and request metadata")

    class Config:
        extra = "allow"


class ConfirmLicensePurchasedInput(BaseModel):
    """Expected input shape for the confirmLicensePurchased transformation.

    The workflow merges queryDevices, getPreventionPolicies, and getSensorUpdatePolicies
    into a single dict keyed by method name. The transformation reads
    queryDevices.resources (or a flat top-level resources list for legacy inputs).
    """
    queryDevices: Optional[QueryDevicesResult] = Field(default=None, description="Merged queryDevices result")
    resources: Optional[List[Any]] = Field(default=None, description="Flat resources list (legacy / direct API format)")
    meta: Optional[Dict[str, Any]] = Field(default=None)

    class Config:
        extra = "allow"
