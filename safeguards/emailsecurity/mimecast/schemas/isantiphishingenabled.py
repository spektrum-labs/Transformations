"""Schema for isantiphishingenabled transformation input (Mimecast).

Source endpoint: POST /api/ttp/impersonation/get-logs
"""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ImpersonationResult(BaseModel):
    impersonationDomainSource: Optional[str] = None
    stringSimilarToDomain: Optional[str] = None
    similarDomain: Optional[str] = None

    class Config:
        extra = "allow"


class ImpersonationLogEntry(BaseModel):
    hits: Optional[int] = Field(None, description="Number of hits for this detection")
    taggedMalicious: Optional[bool] = Field(None, description="Whether the message was tagged as malicious")
    senderAddress: Optional[str] = Field(None, description="Sender email address")
    subject: Optional[str] = Field(None, description="Email subject")
    identifiers: Optional[List[str]] = Field(None, description="Detection identifiers (e.g. newly_observed_domain, internal_user_name, reply_address_mismatch, targeted_threat_dictionary)")
    action: Optional[str] = Field(None, description="Action taken (hold, bounce, none)")
    definition: Optional[str] = Field(None, description="Policy definition name (e.g. Default Impersonation Protect)")
    impersonationResults: Optional[List[ImpersonationResult]] = Field(None, description="Domain similarity details")

    class Config:
        extra = "allow"


class ImpersonationDataEntry(BaseModel):
    impersonationLogs: Optional[List[ImpersonationLogEntry]] = Field(None, description="List of impersonation detection log entries")

    class Config:
        extra = "allow"


class MetaBlock(BaseModel):
    status: Optional[int] = Field(None, description="HTTP status code from Mimecast API")

    class Config:
        extra = "allow"


class IsantiphishingenabledInput(BaseModel):
    """Expected input: response from POST /api/ttp/impersonation/get-logs.
    A successful response (meta.status == 200) confirms TTP Impersonation Protect is configured.

    Note: The API response may arrive as a dict (full response) or as a list
    (unwrapped data array). The transformation handles both shapes; schema
    validation applies only to dict inputs.
    """
    meta: Optional[MetaBlock] = Field(None, description="Mimecast API response metadata")
    data: Optional[List[ImpersonationDataEntry]] = Field(None, description="Array of impersonation log data")
    fail: Optional[List[Any]] = Field(None, description="Mimecast API error array")

    class Config:
        extra = "allow"
