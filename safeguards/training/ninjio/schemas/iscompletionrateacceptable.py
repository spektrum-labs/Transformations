"""Schema for iscompletionrateacceptable transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class StatisticsBlock(BaseModel):
    """Aggregate statistics block."""
    total_enrolled: Optional[int] = Field(None, description="Total enrolled users")
    enrolled: Optional[int] = Field(None, description="Alternate enrolled count field")
    totalEnrolled: Optional[int] = Field(None, description="Alternate enrolled count field (camelCase)")
    total_completed: Optional[int] = Field(None, description="Total completed users")
    completed: Optional[int] = Field(None, description="Alternate completed count field")
    totalCompleted: Optional[int] = Field(None, description="Alternate completed count field (camelCase)")

    class Config:
        extra = "allow"


class TemplateItem(BaseModel):
    """A single training template with enrollment/completion data."""
    total_enrolled: Optional[int] = Field(None, description="Total enrolled users for this template")
    enrolled: Optional[int] = Field(None, description="Alternate enrolled count field")
    totalEnrolled: Optional[int] = Field(None, description="Alternate enrolled count field (camelCase)")
    enrollment_count: Optional[int] = Field(None, description="Alternate enrollment count field")
    total_completed: Optional[int] = Field(None, description="Total completed users for this template")
    completed: Optional[int] = Field(None, description="Alternate completed count field")
    totalCompleted: Optional[int] = Field(None, description="Alternate completed count field (camelCase)")
    completion_count: Optional[int] = Field(None, description="Alternate completion count field")
    completion_rate: Optional[float] = Field(None, description="Direct completion rate for this template")
    completionRate: Optional[float] = Field(None, description="Alternate completion rate field (camelCase)")

    class Config:
        extra = "allow"


class IscompletionrateacceptableInput(BaseModel):
    """Expected input schema for the iscompletionrateacceptable transformation. Criteria key: isCompletionRateAcceptable"""
    completion_rate: Optional[float] = Field(None, description="Direct completion rate (percentage)")
    completionRate: Optional[float] = Field(None, description="Alternate completion rate field (camelCase)")
    total_enrolled: Optional[int] = Field(None, description="Total enrolled users (direct stat)")
    enrolled: Optional[int] = Field(None, description="Alternate enrolled count")
    totalEnrolled: Optional[int] = Field(None, description="Alternate enrolled count (camelCase)")
    total_completed: Optional[int] = Field(None, description="Total completed users (direct stat)")
    completed: Optional[int] = Field(None, description="Alternate completed count")
    totalCompleted: Optional[int] = Field(None, description="Alternate completed count (camelCase)")
    statistics: Optional[StatisticsBlock] = Field(None, description="Aggregate statistics block")
    stats: Optional[StatisticsBlock] = Field(None, description="Alternate aggregate statistics block")
    aggregate: Optional[StatisticsBlock] = Field(None, description="Alternate aggregate statistics block")
    results: Optional[List[TemplateItem]] = Field(None, description="List of training templates")
    data: Optional[Any] = Field(None, description="Alternate key for templates list or nested data")
    templates: Optional[List[TemplateItem]] = Field(None, description="Alternate key for templates list")
    items: Optional[List[TemplateItem]] = Field(None, description="Alternate key for templates list")

    class Config:
        extra = "allow"
