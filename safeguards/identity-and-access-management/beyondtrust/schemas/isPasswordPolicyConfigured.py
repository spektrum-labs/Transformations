"""Schema for isPasswordPolicyConfigured transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class PasswordRule(BaseModel):
    """A BeyondTrust password rule/policy entry."""
    MinimumLength: Optional[Union[int, float]] = None

    class Config:
        extra = "allow"


class IsPasswordPolicyConfiguredInput(BaseModel):
    """
    Expected input shape for the isPasswordPolicyConfigured transformation.
    Accepts either a bare list of rules or a dict with PasswordRules key.
    """
    PasswordRules: Optional[List[PasswordRule]] = None
    items: Optional[List[PasswordRule]] = None
    results: Optional[List[PasswordRule]] = None

    class Config:
        extra = "allow"
