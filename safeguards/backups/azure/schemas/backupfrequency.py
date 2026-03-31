"""Schema for backupfrequency transformation input."""
from typing import Optional
from pydantic import BaseModel, Field


class SchedulePolicy(BaseModel):
    """Schedule policy for backup frequency."""
    scheduleFrequencyInMins: Optional[int] = Field(
        default=None,
        description="Backup schedule frequency in minutes"
    )

    class Config:
        extra = "allow"


class BackupFrequencyProperties(BaseModel):
    """Properties containing the schedule policy."""
    schedulePolicy: Optional[SchedulePolicy] = Field(
        default=None,
        description="Schedule policy configuration"
    )

    class Config:
        extra = "allow"


class BackupfrequencyInput(BaseModel):
    """Expected input schema for the backupfrequency transformation. Criteria key: backupFrequency"""
    properties: Optional[BackupFrequencyProperties] = Field(
        default=None,
        description="Properties containing schedule policy for backup frequency evaluation"
    )

    class Config:
        extra = "allow"
