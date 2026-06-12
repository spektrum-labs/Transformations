"""Schema for isipallowlistenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsipallowlistenabledInput(BaseModel):
    """
    Expected input schema for the isipallowlistenabled transformation.
    Criteria key: isIPAllowlistEnabled
    """

    class Config:
        extra = "allow"
