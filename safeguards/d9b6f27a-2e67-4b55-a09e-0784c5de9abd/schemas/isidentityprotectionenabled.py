"""Schema for isidentityprotectionenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsidentityprotectionenabledInput(BaseModel):
    """
    Expected input schema for the isidentityprotectionenabled transformation.
    Criteria key: isidentityprotectionenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
