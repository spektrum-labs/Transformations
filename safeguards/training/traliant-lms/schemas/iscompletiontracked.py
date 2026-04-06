"""Schema for iscompletiontracked transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscompletiontrackedInput(BaseModel):
    """
    Expected input schema for the iscompletiontracked transformation.
    Vendor: Traliant Lms
    Category: training

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
