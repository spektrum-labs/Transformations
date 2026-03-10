"""Schema for isdatasourcesconfigured transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActivityRecord(BaseModel):
    """A single Netwrix activity record for data source evaluation."""
    DataSource: Optional[str] = Field(None, description="Name of the data source that generated this record")
    dataSource: Optional[str] = Field(None, description="Alternate casing for data source name")

    class Config:
        extra = "allow"


class IsdatasourcesconfiguredInput(BaseModel):
    """Expected input schema for the isdatasourcesconfigured transformation. Criteria key: isDataSourcesConfigured"""
    ActivityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records (primary key)")
    activityRecordList: Optional[List[ActivityRecord]] = Field(None, description="Array of Netwrix activity records (alternate casing)")

    class Config:
        extra = "allow"
