"""Schema for recoverytestcompleted transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class JobProperties(BaseModel):
    """Properties of a backup job."""
    operation: Optional[str] = Field(
        default=None,
        description="Type of operation (e.g., Restore, Backup)"
    )
    status: Optional[str] = Field(
        default=None,
        description="Job status (e.g., Completed, InProgress, Failed)"
    )
    endTime: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp of when the job completed"
    )

    class Config:
        extra = "allow"


class BackupJob(BaseModel):
    """A backup job in Azure Recovery Services."""
    properties: Optional[JobProperties] = Field(
        default=None,
        description="Properties of the backup job"
    )

    class Config:
        extra = "allow"


class RecoverytestcompletedInput(BaseModel):
    """Expected input schema for the recoverytestcompleted transformation. Criteria key: recoveryTestCompleted"""
    value: Optional[List[BackupJob]] = Field(
        default=None,
        description="List of backup jobs to check for completed restore operations"
    )

    class Config:
        extra = "allow"
