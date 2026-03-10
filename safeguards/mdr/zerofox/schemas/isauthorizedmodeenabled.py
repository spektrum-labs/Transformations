"""Schema for isauthorizedmodeenabled transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RemediationEntity(BaseModel):
    """An entity with auto-remediation settings."""
    auto_remediation_enabled: Optional[Any] = Field(None, description="Whether auto-remediation (takedown authorization) is enabled (bool or string)")

    class Config:
        extra = "allow"


class IsauthorizedmodeenabledInput(BaseModel):
    """Expected input schema for the isauthorizedmodeenabled transformation. Criteria key: isAuthorizedModeEnabled"""
    entities: Optional[List[RemediationEntity]] = Field(None, description="List of entities (also checked as 'results' or 'items')")
    results: Optional[List[RemediationEntity]] = Field(None, description="Alternate key for entities list")
    items: Optional[List[RemediationEntity]] = Field(None, description="Alternate key for entities list")

    class Config:
        extra = "allow"
