"""Schema for isremovablemediacontrolled transformation input."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class IsremovablemediacontrolledInput(BaseModel):
    """
    Expected input schema for the isremovablemediacontrolled transformation.
    Criteria key: isRemovableMediaControlled

    Validates that removable media control is enabled on the
    endpoint protection platform.
    """

    isRemovableMediaControlled: Optional[bool] = None

    class Config:
        extra = "allow"
