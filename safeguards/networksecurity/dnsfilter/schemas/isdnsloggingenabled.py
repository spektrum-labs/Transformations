"""Schema for isdnsloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdnsloggingenabledInput(BaseModel):
    """
    Expected input schema for the isdnsloggingenabled transformation.
    Criteria key: isDNSLoggingEnabled

    Validates that DNS query logging is enabled by checking the
    total_queries traffic report endpoint.
    """

    total_queries: Optional[int] = None
    totalQueries: Optional[int] = None
    total: Optional[int] = None
    count: Optional[int] = None
    queries: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None
    logs: Optional[List[Dict[str, Any]]] = None
    logging_enabled: Optional[bool] = None
    loggingEnabled: Optional[bool] = None

    class Config:
        extra = "allow"
