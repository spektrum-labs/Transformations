"""Schema for lastsuccessfulbackupage transformation input.

With merge=false, the input is the protectedItems array directly — a list of
vault entries, each containing a 'value' array of protected backup items.

Note: Since the input is a list and Token-Service only provides BaseModel (not
RootModel), schema validation is skipped for list inputs. The transformation's
extract_protected_items() handles all input shapes.
"""
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
    """Expected input schema for the lastsuccessfulbackupage transformation. Criteria key: lastSuccessfulBackupAge

    Accepts dict inputs with protectedItems or value keys.
    List inputs (merge=false) bypass schema validation.
    """
    protectedItems: Optional[List[Any]] = Field(
        default=None,
        description="List of vault entries, each containing a 'value' array of protected items"
    )
    value: Optional[List[ProtectedItem]] = Field(
        default=None,
        description="Direct list of protected backup items (single vault format)"
    )

    class Config:
        extra = "allow"
