"""Schema for islegacyauthblocked transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IslegacyauthblockedInput(BaseModel):
    """
    Expected input schema for the islegacyauthblocked transformation.
    Criteria key: islegacyauthblocked
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
