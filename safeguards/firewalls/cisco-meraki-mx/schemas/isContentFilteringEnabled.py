from pydantic import BaseModel
from typing import Optional, List


class IsContentFilteringEnabledInput(BaseModel):
    """Input schema for the isContentFilteringEnabled transformation."""
    allowedUrlPatterns: Optional[List[str]] = None
    blockedUrlPatterns: Optional[List[str]] = None
    blockedUrlCategories: Optional[List[str]] = None
    urlCategoryListSize: Optional[str] = None

    class Config:
        extra = "allow"
