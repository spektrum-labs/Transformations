"""Schema for isactivityauditingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsactivityauditingenabledInput(BaseModel):
    """
    Expected input schema for the isactivityauditingenabled transformation.
    Criteria key: isActivityAuditingEnabled
    """

    class Config:
        extra = "allow"
