"""Schema for isrbacimplemented transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsrbacimplementedInput(BaseModel):
    """
    Expected input schema for the isrbacimplemented transformation.
    Vendor: Cyberark
    Category: iam
    """

    class Config:
        extra = "allow"
