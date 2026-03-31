"""Schema for isbackupenabled transformation input."""

from typing import Any, Optional
from pydantic import BaseModel


class IsbackupenabledInput(BaseModel):
    """
    Expected input schema for the isbackupenabled transformation.
    Criteria key: isbackupenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
