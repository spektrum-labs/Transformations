"""Schema for iscloudmonitoringenabled transformation input.

After Token-Service unwraps the 'data' key, input arrives as a list of
endpoint objects. Since Token-Service only provides BaseModel (not
RootModel), schema validation is skipped for list inputs. The
transformation handles both list and dict inputs directly.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EndpointItem(BaseModel):
    """A single endpoint object from the Red Canary endpoints API."""
    type: Optional[str] = None
    id: Optional[Any] = None
    attributes: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class IscloudmonitoringenabledInput(BaseModel):
    """Expected input schema for the iscloudmonitoringenabled transformation.
    Criteria key: isCloudMonitoringEnabled

    Accepts dict inputs with data or value keys.
    List inputs (after Token-Service unwrapping) bypass schema validation.
    """
    data: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of monitored endpoint objects"
    )
    meta: Optional[Dict[str, Any]] = None
    links: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
