"""Schema for isemailloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ResultInfo(BaseModel):
    """Pagination info from Cloudflare API response."""

    total_count: Optional[int] = None

    class Config:
        extra = "allow"


class IsemailloggingenabledInput(BaseModel):
    """
    Expected input schema for the isemailloggingenabled transformation.
    Criteria key: isEmailLoggingEnabled

    Checks if Cloudflare Email Security is capturing and logging email
    events via the investigate endpoint response.
    """

    success: Optional[bool] = None
    result: Optional[List[Dict[str, Any]]] = None
    results: Optional[List[Dict[str, Any]]] = None
    messages: Optional[List[Dict[str, Any]]] = None
    result_info: Optional[ResultInfo] = None
    auditLogs: Optional[List[Dict[str, Any]]] = None
    logs: Optional[List[Dict[str, Any]]] = None
    events: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
