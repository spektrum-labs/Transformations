"""Schema for isbehavioralmonitoringvalid transformation input."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class IsbehavioralmonitoringvalidInput(BaseModel):
    """
    Expected input schema for the isbehavioralmonitoringvalid transformation.
    Criteria key: isBehavioralMonitoringValid

    Validates that behavioral monitoring is functioning on the
    endpoint protection platform.
    """

    isBehavioralMonitoringValid: Optional[bool] = None

    class Config:
        extra = "allow"
