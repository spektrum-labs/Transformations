"""Schema for isretentioncompliant transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActivityRecord(BaseModel):
    """A single Netwrix activity record for retention evaluation."""
    When: Optional[str] = Field(None, description="Timestamp of the activity record in ISO 8601 format")
    when: Optional[str] = Field(None, description="Alternate casing for timestamp of the activity record")

    class Config:
        extra = "allow"


class IsretentioncompliantInput(BaseModel):
    """Expected input schema for the isretentioncompliant transformation. Criteria key: isRetentionCompliant"""
    ActivityRecordSearch: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from search endpoint (primary key)")
    activityRecordSearch: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from search endpoint (alternate casing)")
    ActivityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from list endpoint (fallback key)")
    activityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from list endpoint (fallback alternate casing)")

    class Config:
        extra = "allow"
