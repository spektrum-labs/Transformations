"""Schema for confirmpasswordpolicyenforced transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmpasswordpolicyenforcedInput(BaseModel):
    """
    Expected input schema for the confirmpasswordpolicyenforced transformation.
    Criteria key: confirmpasswordpolicyenforced
    """

    apiResponse: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
