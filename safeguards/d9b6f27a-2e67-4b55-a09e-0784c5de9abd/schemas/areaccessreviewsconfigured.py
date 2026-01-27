"""Schema for areaccessreviewsconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AreaccessreviewsconfiguredInput(BaseModel):
    """
    Expected input schema for the areaccessreviewsconfigured transformation.
    Criteria key: areaccessreviewsconfigured
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
