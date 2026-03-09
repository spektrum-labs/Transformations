"""Schema for iscloudmonitoringenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscloudmonitoringenabledInput(BaseModel):
    """
    Expected input schema for the iscloudmonitoringenabled transformation.
    Criteria key: isCloudMonitoringEnabled

    Validates that cloud detection detectors are configured and active
    by checking the detectors endpoint.
    """

    detectors: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
