"""Schema for iscriticalfindingsmonitored transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FindingRecord(BaseModel):
    """A single finding entry from the SAFE findings endpoint."""

    updatedAt: Optional[str] = Field(None, description="Timestamp when the finding was last updated")
    lastUpdated: Optional[str] = Field(None, description="Alternate last-updated timestamp")
    assessedAt: Optional[str] = Field(None, description="Timestamp when the finding was assessed")
    createdAt: Optional[str] = Field(None, description="Timestamp when the finding was created")

    class Config:
        extra = "allow"


class IscriticalfindingsmonitoredInput(BaseModel):
    """Expected input schema for the iscriticalfindingsmonitored transformation. Criteria key: isCriticalFindingsMonitored"""

    totalCount: Optional[int] = Field(None, description="Total number of critical findings")
    size: Optional[int] = Field(None, description="Alternate total count field")
    values: Optional[List[FindingRecord]] = Field(None, description="List of finding records")
    findings: Optional[List[FindingRecord]] = Field(None, description="Alternate key for finding records")
    data: Optional[List[FindingRecord]] = Field(None, description="Alternate key for finding records")

    class Config:
        extra = "allow"
