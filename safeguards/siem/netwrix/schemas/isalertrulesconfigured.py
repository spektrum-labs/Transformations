"""Schema for isalertrulesconfigured transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActivityRecord(BaseModel):
    """A single Netwrix activity record for alert rules evaluation."""
    Action: Optional[str] = Field(None, description="Action type of the activity record (e.g. Alert, Alert Triggered)")
    action: Optional[str] = Field(None, description="Alternate casing for action type")

    class Config:
        extra = "allow"


class IsalertrulesconfiguredInput(BaseModel):
    """Expected input schema for the isalertrulesconfigured transformation. Criteria key: isAlertRulesConfigured"""
    ActivityRecordSearch: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from search endpoint (primary key)")
    activityRecordSearch: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from search endpoint (alternate casing)")
    ActivityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from list endpoint (fallback key)")
    activityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from list endpoint (fallback alternate casing)")

    class Config:
        extra = "allow"
