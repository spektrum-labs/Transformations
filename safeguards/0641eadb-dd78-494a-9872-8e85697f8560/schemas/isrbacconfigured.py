"""Schema for isrbacconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsrbacconfiguredInput(BaseModel):
    """
    Expected input schema for the isrbacconfigured transformation.
    Criteria key: isRBACConfigured
    """

    class Config:
        extra = "allow"
