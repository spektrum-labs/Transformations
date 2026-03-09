"""Schema for isentitymonitoringactive transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EntityPolicy(BaseModel):
    """Policy attached to a monitored entity."""
    enabled: Optional[Any] = Field(None, description="Whether the monitoring policy is enabled (bool or string)")

    class Config:
        extra = "allow"


class MonitoredEntity(BaseModel):
    """A protected entity with an optional monitoring policy."""
    policy: Optional[EntityPolicy] = Field(None, description="Monitoring policy for this entity")

    class Config:
        extra = "allow"


class IsentitymonitoringactiveInput(BaseModel):
    """Expected input schema for the isentitymonitoringactive transformation. Criteria key: isEntityMonitoringActive"""
    entities: Optional[List[MonitoredEntity]] = Field(None, description="List of protected entities (also checked as 'results' or 'items')")
    results: Optional[List[MonitoredEntity]] = Field(None, description="Alternate key for entities list")
    items: Optional[List[MonitoredEntity]] = Field(None, description="Alternate key for entities list")

    class Config:
        extra = "allow"
