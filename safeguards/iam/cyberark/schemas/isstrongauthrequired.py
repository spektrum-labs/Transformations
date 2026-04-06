"""Schema for isstrongauthrequired transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsstrongauthrequiredInput(BaseModel):
    """
    Expected input schema for the isstrongauthrequired transformation.
    Vendor: Cyberark
    Category: iam
    """

    class Config:
        extra = "allow"
