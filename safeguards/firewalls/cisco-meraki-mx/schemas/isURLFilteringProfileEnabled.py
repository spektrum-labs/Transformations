from pydantic import BaseModel
from typing import List, Optional


class IsURLFilteringProfileEnabledInput(BaseModel):
    """Input schema for the isURLFilteringProfileEnabled transformation."""
    allowedUrlPatterns: Optional[List[str]] = None
    blockedUrlPatterns: Optional[List[str]] = None
    blockedUrlCategories: Optional[List[dict]] = None
    urlCategoryListSize: Optional[str] = None

    class Config:
        extra = "allow"
