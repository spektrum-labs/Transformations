"""Schema for islifecyclemanagementenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IslifecyclemanagementenabledInput(BaseModel):
    """
    Expected input schema for the islifecyclemanagementenabled transformation.
    Vendor: Cyberark
    Category: iam
    """

    class Config:
        extra = "allow"
