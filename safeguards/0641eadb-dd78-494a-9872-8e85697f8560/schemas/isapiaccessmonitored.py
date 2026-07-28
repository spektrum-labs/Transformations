"""Schema for isapiaccessmonitored transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsapiaccessmonitoredInput(BaseModel):
    """
    Expected input schema for the isapiaccessmonitored transformation.
    Criteria key: isApiAccessMonitored
    """

    class Config:
        extra = "allow"
