"""Schema for ispasswordpolicyconfigured transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class PasswordRule(BaseModel):
    """A single password rule/policy entry."""
    MinimumLength: Optional[Union[int, float]] = None

    class Config:
        extra = "allow"


class IspasswordpolicyconfiguredInput(BaseModel):
    """
    Expected input schema for the ispasswordpolicyconfigured transformation.
    Criteria key: isPasswordPolicyConfigured
    """
    PasswordRules: Optional[List[PasswordRule]] = None
    items: Optional[List[PasswordRule]] = None
    results: Optional[List[PasswordRule]] = None

    class Config:
        extra = "allow"
