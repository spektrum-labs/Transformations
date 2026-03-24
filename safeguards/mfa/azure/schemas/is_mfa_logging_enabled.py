"""Schema for is_mfa_logging_enabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsMfaLoggingEnabledInput(BaseModel):
    """
    Expected input schema for the is_mfa_logging_enabled transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
