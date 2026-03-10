"""Schema for isbackuptypesscheduled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScheduleFrequency(BaseModel):
    """Nested schedule frequency or backup options block."""
    backupType: Optional[str] = None
    scheduleBackupLevel: Optional[str] = None
    backupLevel: Optional[str] = None

    class Config:
        extra = "allow"


class Schedule(BaseModel):
    """Single schedule entry within a backup plan."""
    backupType: Optional[str] = None
    scheduleBackupLevel: Optional[str] = None
    backupLevel: Optional[str] = None
    scheduleFrequency: Optional[ScheduleFrequency] = None
    backupOpts: Optional[ScheduleFrequency] = None
    dataBackupOption: Optional[ScheduleFrequency] = None

    class Config:
        extra = "allow"


class SchedulePolicy(BaseModel):
    """Nested schedule policy block."""
    schedules: Optional[List[Schedule]] = None

    class Config:
        extra = "allow"


class BackupWindow(BaseModel):
    """RPO backup window entry."""
    backupType: Optional[str] = None
    scheduleBackupLevel: Optional[str] = None
    backupLevel: Optional[str] = None

    class Config:
        extra = "allow"


class RPO(BaseModel):
    """RPO configuration block."""
    backupWindow: Optional[List[BackupWindow]] = None
    slaBackupWindow: Optional[List[BackupWindow]] = None

    class Config:
        extra = "allow"


class PlanSummary(BaseModel):
    """Summary block within a backup plan."""
    schedules: Optional[List[Schedule]] = None
    schedule: Optional[List[Schedule]] = None
    schedulePolicy: Optional[SchedulePolicy] = None
    rpo: Optional[RPO] = None

    class Config:
        extra = "allow"


class Plan(BaseModel):
    """Single backup plan entry."""
    summary: Optional[PlanSummary] = None
    schedules: Optional[List[Schedule]] = None
    schedule: Optional[List[Schedule]] = None
    schedulePolicy: Optional[SchedulePolicy] = None
    rpo: Optional[RPO] = None

    class Config:
        extra = "allow"


class IsbackuptypesscheduledInput(BaseModel):
    """
    Expected input schema for the isbackuptypesscheduled transformation.
    Criteria key: isBackupTypesScheduled
    """
    plans: Optional[List[Plan]] = None
    planList: Optional[List[Plan]] = None
    plan: Optional[Plan] = None
    schedules: Optional[List[Schedule]] = None
    schedule: Optional[List[Schedule]] = None
    schedulePolicy: Optional[SchedulePolicy] = None
    rpo: Optional[RPO] = None

    class Config:
        extra = "allow"
