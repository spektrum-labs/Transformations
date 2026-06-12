"""Schema for isssoenforced transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsssoenforcedInput(BaseModel):
    """
    Expected input schema for the isssoenforced transformation.
    Criteria key: isSSOEnforced
    """

    class Config:
        extra = "allow"
