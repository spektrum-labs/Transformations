"""Schema for isalertingconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsalertingconfiguredInput(BaseModel):
    """
    Expected input schema for the isalertingconfigured transformation.
    Criteria key: isAlertingConfigured

    Validates that detection alerting is configured by checking
    the detections endpoint for detection activity.
    """

    detections: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
