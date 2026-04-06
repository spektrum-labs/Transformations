"""Schema for isriskprioritizationtrue transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsriskprioritizationtrueInput(BaseModel):
    """
    Expected input schema for the isriskprioritizationtrue transformation.
    Vendor: Plextrac
    Category: asm

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
