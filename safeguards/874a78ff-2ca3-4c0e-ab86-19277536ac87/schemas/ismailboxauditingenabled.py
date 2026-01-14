"""Schema for ismailboxauditingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmailboxauditingenabledInput(BaseModel):
    """
    Expected input schema for the ismailboxauditingenabled transformation.
    Criteria key: ismailboxauditingenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
