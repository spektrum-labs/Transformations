"""Schema for isprivilegedidentitymanagementenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsprivilegedidentitymanagementenabledInput(BaseModel):
    """
    Expected input schema for the isprivilegedidentitymanagementenabled transformation.
    Criteria key: isprivilegedidentitymanagementenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
