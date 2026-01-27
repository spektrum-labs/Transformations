"""Schema for issamlenforced transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssamlenforcedInput(BaseModel):
    """
    Expected input schema for the issamlenforced transformation.
    Criteria key: issamlenforced
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
