"""Schema for lastsuccessfulbackupage transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProtectedItemProperties(BaseModel):
    """Properties of a protected backup item."""
    lastBackupTime: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp of the last successful backup"
    )

    class Config:
        extra = "allow"


class ProtectedItem(BaseModel):
    """A protected backup item in Azure Recovery Services."""
    properties: Optional[ProtectedItemProperties] = Field(
        default=None,
        description="Properties of the protected item including last backup time"
    )

    class Config:
        extra = "allow"


class LastsuccessfulbackupageInput(BaseModel):
    """Expected input schema for the lastsuccessfulbackupage transformation. Criteria key: lastSuccessfulBackupAge"""
    value: Optional[List[ProtectedItem]] = Field(
        default=None,
        description="List of protected backup items with their last backup times"
    )

    class Config:
        extra = "allow"
