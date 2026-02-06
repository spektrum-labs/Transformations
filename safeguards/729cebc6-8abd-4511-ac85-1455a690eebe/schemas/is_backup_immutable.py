"""Schema for is_backup_immutable transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsBackupImmutableInput(BaseModel):
    """
    Expected input schema for the is_backup_immutable transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
