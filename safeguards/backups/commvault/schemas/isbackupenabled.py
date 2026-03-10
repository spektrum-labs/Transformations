"""Schema for isbackupenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PlanSummary(BaseModel):
    """Summary block within a backup plan."""
    planStatusFlag: Optional[int] = None
    numDevices: Optional[int] = None
    numberOfEntities: Optional[int] = None

    class Config:
        extra = "allow"


class Plan(BaseModel):
    """Single backup plan entry."""
    summary: Optional[PlanSummary] = None
    planStatusFlag: Optional[int] = None
    numDevices: Optional[int] = None
    numberOfEntities: Optional[int] = None

    class Config:
        extra = "allow"


class IsbackupenabledInput(BaseModel):
    """
    Expected input schema for the isbackupenabled transformation.
    Criteria key: isBackupEnabled
    """
    plans: Optional[List[Plan]] = None
    planList: Optional[List[Plan]] = None
    value: Optional[List[Plan]] = None

    class Config:
        extra = "allow"
