"""Schema for isdefaultdenyconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CustomCategory(BaseModel):
    """A custom URL filtering/blocking category."""

    class Config:
        extra = "allow"


class DataPayload(BaseModel):
    """Inner data payload containing custom categories."""

    customCategories: Optional[List[CustomCategory]] = None

    class Config:
        extra = "allow"


class IsdefaultdenyconfiguredInput(BaseModel):
    """Expected input schema for the isdefaultdenyconfigured transformation. Criteria key: isDefaultDenyConfigured"""

    data: Optional[DataPayload] = None

    class Config:
        extra = "allow"
