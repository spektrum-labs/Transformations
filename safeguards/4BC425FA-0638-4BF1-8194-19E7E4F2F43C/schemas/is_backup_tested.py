"""Schema for is_backup_tested transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class CloudTrailEvent(BaseModel):
    """Single CloudTrail event record."""
    EventId: Optional[str] = None
    EventName: Optional[str] = None
    EventTime: Optional[str] = None
    EventSource: Optional[str] = None
    Username: Optional[str] = None
    Resources: Optional[List[Dict[str, Any]]] = None
    CloudTrailEvent: Optional[str] = None

    class Config:
        extra = "allow"


class LookupEventsResult(BaseModel):
    """Result from CloudTrail LookupEvents API."""
    Events: Optional[Union[List[CloudTrailEvent], None]] = None
    NextToken: Optional[str] = None

    class Config:
        extra = "allow"


class LookupEventsResponse(BaseModel):
    """AWS CloudTrail LookupEvents response."""
    LookupEventsResult: Optional[LookupEventsResult] = None
    ResponseMetadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class IsBackupTestedInput(BaseModel):
    """
    Expected input schema for the is_backup_tested transformation.

    This schema validates the CloudTrail LookupEvents API response that checks
    for restore events to determine if backups have been tested.
    """

    LookupEventsResponse: Optional[LookupEventsResponse] = Field(
        default=None,
        description="CloudTrail LookupEvents response containing restore event history"
    )

    class Config:
        extra = "allow"
