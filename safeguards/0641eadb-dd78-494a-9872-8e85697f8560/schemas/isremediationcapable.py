"""Schema for isremediationcapable transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsremediationcapableInput(BaseModel):
    """
    Expected input schema for the isremediationcapable transformation.
    Criteria key: isRemediationCapable
    """

    class Config:
        extra = "allow"
