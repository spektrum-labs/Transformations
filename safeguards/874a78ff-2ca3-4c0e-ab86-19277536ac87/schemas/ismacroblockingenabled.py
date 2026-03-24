"""Schema for ismacroblockingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmacroblockingtenabledInput(BaseModel):
    """
    Expected input schema for the ismacroblockingenabled transformation.
    Criteria key: isMacroBlockingEnabled
    """

    EnableFileFilter: Optional[bool] = None
    FileTypes: Optional[List[str]] = None

    class Config:
        extra = "allow"
