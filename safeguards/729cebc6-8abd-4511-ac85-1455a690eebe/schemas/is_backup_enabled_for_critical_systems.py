"""Schema for is_backup_enabled_for_critical_systems transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsBackupEnabledForCriticalSystemsInput(BaseModel):
    """
    Expected input schema for the is_backup_enabled_for_critical_systems transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
