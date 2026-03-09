"""Schema for isincidentworkflowconfigured transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActivityRecord(BaseModel):
    """A single Netwrix activity record for incident workflow evaluation."""
    DataSource: Optional[str] = Field(None, description="Name of the data source that generated this record")
    dataSource: Optional[str] = Field(None, description="Alternate casing for data source name")
    Action: Optional[str] = Field(None, description="Action type of the activity record (e.g. Run Script, Ticket Created)")
    action: Optional[str] = Field(None, description="Alternate casing for action type")
    ObjectType: Optional[str] = Field(None, description="Object type of the activity record (e.g. Alert Response, Incident)")
    objectType: Optional[str] = Field(None, description="Alternate casing for object type")

    class Config:
        extra = "allow"


class IsincidentworkflowconfiguredInput(BaseModel):
    """Expected input schema for the isincidentworkflowconfigured transformation. Criteria key: isIncidentWorkflowConfigured"""
    ActivityRecordSearch: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from search endpoint (primary key)")
    activityRecordSearch: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from search endpoint (alternate casing)")
    ActivityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from list endpoint (fallback key)")
    activityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records from list endpoint (fallback alternate casing)")

    class Config:
        extra = "allow"
