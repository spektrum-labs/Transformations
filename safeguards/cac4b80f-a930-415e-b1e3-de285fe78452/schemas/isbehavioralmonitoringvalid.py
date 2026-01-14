"""Schema for isbehavioralmonitoringvalid transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsbehavioralmonitoringvalidInput(BaseModel):
    """
    Expected input schema for the isbehavioralmonitoringvalid transformation.
    Criteria key: isbehavioralmonitoringvalid
    """

    message: Optional[str] = None
    status: Optional[str] = None

    class Config:
        extra = "allow"
