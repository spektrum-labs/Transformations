"""Schema for requiredcoveragepercentage transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class CoverageEntityPolicy(BaseModel):
    """Policy attached to an entity for coverage calculation."""
    enabled: Optional[Any] = Field(None, description="Whether the monitoring policy is enabled (bool or string)")

    class Config:
        extra = "allow"


class CoverageEntity(BaseModel):
    """An entity with a monitoring policy used for coverage percentage calculation."""
    policy: Optional[Union[CoverageEntityPolicy, bool]] = Field(None, description="Monitoring policy for this entity (dict with 'enabled' key, or bool)")

    class Config:
        extra = "allow"


class RequiredcoveragepercentageInput(BaseModel):
    """Expected input schema for the requiredcoveragepercentage transformation. Criteria key: requiredCoveragePercentage"""
    entities: Optional[List[CoverageEntity]] = Field(None, description="List of entities (also checked as 'results' or 'items')")
    results: Optional[List[CoverageEntity]] = Field(None, description="Alternate key for entities list")
    items: Optional[List[CoverageEntity]] = Field(None, description="Alternate key for entities list")

    class Config:
        extra = "allow"
