"""Schema for isurlrewriteenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsurlrewriteenabledInput(BaseModel):
    """
    Expected input schema for the isurlrewriteenabled transformation.
    Criteria key: isURLRewriteEnabled

    Checks URL rewrite/protection settings, URL defense, safe links,
    and URL-related policies from Mimecast.
    """

    urlRewriteEnabled: Optional[bool] = None
    urlProtection: Optional[bool] = None
    urlDefense: Optional[bool] = None
    safeLinks: Optional[bool] = None
    enabled: Optional[bool] = None
    policies: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
