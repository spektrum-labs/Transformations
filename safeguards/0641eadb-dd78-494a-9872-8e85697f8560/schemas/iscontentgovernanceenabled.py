"""Schema for iscontentgovernanceenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscontentgovernanceenabledInput(BaseModel):
    """
    Expected input schema for the iscontentgovernanceenabled transformation.
    Criteria key: isContentGovernanceEnabled
    """

    class Config:
        extra = "allow"
