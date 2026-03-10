"""Schema for isbackuptested transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class JobSummary(BaseModel):
    """Job summary details within a job entry."""
    jobType: Optional[str] = None
    operationType: Optional[str] = None
    status: Optional[str] = None
    jobStatus: Optional[str] = None
    jobStartTime: Optional[Union[int, str]] = None
    startTime: Optional[Union[int, str]] = None

    class Config:
        extra = "allow"


class Job(BaseModel):
    """Single job entry, may contain a nested jobSummary."""
    jobSummary: Optional[JobSummary] = None
    jobType: Optional[str] = None
    operationType: Optional[str] = None
    status: Optional[str] = None
    jobStatus: Optional[str] = None
    jobStartTime: Optional[Union[int, str]] = None
    startTime: Optional[Union[int, str]] = None

    class Config:
        extra = "allow"


class IsbackuptestedInput(BaseModel):
    """
    Expected input schema for the isbackuptested transformation.
    Criteria key: isBackupTested
    """
    jobs: Optional[List[Job]] = None
    jobList: Optional[List[Job]] = None
    items: Optional[List[Job]] = None

    class Config:
        extra = "allow"
