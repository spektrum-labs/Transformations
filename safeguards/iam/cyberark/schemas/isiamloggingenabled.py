"""Schema for isiamloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsiamloggingenabledInput(BaseModel):
    """
    Expected input schema for the isiamloggingenabled transformation.
    Vendor: Cyberark
    Category: iam
    """

    class Config:
        extra = "allow"
