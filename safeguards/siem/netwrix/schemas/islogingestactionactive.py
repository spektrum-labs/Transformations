"""Schema for islogingestactionactive transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActivityRecord(BaseModel):
    """A single Netwrix activity record for log ingestion evaluation."""
    When: Optional[str] = Field(None, description="Timestamp of the activity record in ISO 8601 format")
    when: Optional[str] = Field(None, description="Alternate casing for timestamp of the activity record")

    class Config:
        extra = "allow"


class IslogingestactionactiveInput(BaseModel):
    """Expected input schema for the islogingestactionactive transformation. Criteria key: isLogIngestActionActive"""
    ActivityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records (primary key)")
    activityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records (alternate casing)")

    class Config:
        extra = "allow"
