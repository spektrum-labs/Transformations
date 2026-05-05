from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsMDREnabledInput(BaseModel):
    """Input schema for the isMDREnabled transformation (Red Canary getEndpoints response)."""

    class Data(BaseModel):
        type: Optional[str] = None
        id: Optional[Any] = None

        class Config:
            extra = "allow"

    class Meta(BaseModel):
        api_version: Optional[str] = None
        total_items: Optional[int] = None

        class Config:
            extra = "allow"

    data: Optional[List[Any]] = None
    meta: Optional[Meta] = None

    class Config:
        extra = "allow"
