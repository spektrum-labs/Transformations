"""Schema for isurlrewriteenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RuleAction(BaseModel):
    """Email routing rule action."""

    type: Optional[str] = None

    class Config:
        extra = "allow"


class RoutingRule(BaseModel):
    """Email routing rule from Cloudflare zones API."""

    name: Optional[str] = None
    enabled: Optional[bool] = None
    actions: Optional[List[RuleAction]] = None
    matchers: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"


class IsurlrewriteenabledInput(BaseModel):
    """
    Expected input schema for the isurlrewriteenabled transformation.
    Criteria key: isURLRewriteEnabled

    Checks email routing rules for URL-related actions and link
    scanning configuration in Cloudflare Email Security.
    """

    success: Optional[bool] = None
    result: Optional[List[RoutingRule]] = None
    rules: Optional[List[RoutingRule]] = None
    results: Optional[List[RoutingRule]] = None
    settings: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
