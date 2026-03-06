"""Schema for isantiphishingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EmailMessage(BaseModel):
    """Single email message from Cloudflare Email Security investigate endpoint."""

    id: Optional[str] = None
    postfix_id: Optional[str] = None
    final_disposition: Optional[str] = None
    subject: Optional[str] = None
    from_: Optional[str] = Field(None, alias="from")

    class Config:
        extra = "allow"


class ResultInfo(BaseModel):
    """Pagination info from Cloudflare API response."""

    count: Optional[int] = None
    total_count: Optional[int] = None
    page: Optional[int] = None
    per_page: Optional[int] = None

    class Config:
        extra = "allow"


class IsantiphishingenabledInput(BaseModel):
    """
    Expected input schema for the isantiphishingenabled transformation.
    Criteria key: isAntiPhishingEnabled

    Checks for email detections from the Cloudflare Email Security
    investigate endpoint, including disposition types (MALICIOUS,
    SUSPICIOUS, SPOOF).
    """

    success: Optional[bool] = None
    result: Optional[List[EmailMessage]] = None
    results: Optional[List[EmailMessage]] = None
    messages: Optional[List[EmailMessage]] = None
    result_info: Optional[ResultInfo] = None

    class Config:
        extra = "allow"
