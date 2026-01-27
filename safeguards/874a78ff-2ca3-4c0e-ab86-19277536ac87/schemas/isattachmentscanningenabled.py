"""Schema for isattachmentscanningenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsattachmentscanningenabledInput(BaseModel):
    """
    Expected input schema for the isattachmentscanningenabled transformation.
    Criteria key: isattachmentscanningenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
