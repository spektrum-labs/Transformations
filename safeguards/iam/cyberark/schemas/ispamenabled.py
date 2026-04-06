"""Schema for ispamenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IspamenabledInput(BaseModel):
    """
    Expected input schema for the ispamenabled transformation.
    Vendor: Cyberark
    Category: iam
    """

    class Config:
        extra = "allow"
