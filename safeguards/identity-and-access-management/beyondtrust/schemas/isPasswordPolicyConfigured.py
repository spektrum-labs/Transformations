"""Schema for isPasswordPolicyConfigured transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class PasswordRule(BaseModel):
    """A single password rule/policy entry from the BeyondTrust PasswordRules endpoint."""
    PasswordRuleID: Optional[int] = None
    Name: Optional[str] = None
    Description: Optional[str] = None
    MinimumLength: Optional[Union[int, float]] = None
    MaximumLength: Optional[Union[int, float]] = None
    UpperAlpha: Optional[Union[bool, str]] = None
    LowerAlpha: Optional[Union[bool, str]] = None
    Numeric: Optional[Union[bool, str]] = None
    Special: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IsPasswordPolicyConfiguredInput(BaseModel):
    """Expected input shape for the isPasswordPolicyConfigured transformation."""
    PasswordRules: Optional[List[PasswordRule]] = None
    items: Optional[List[PasswordRule]] = None
    results: Optional[List[PasswordRule]] = None

    class Config:
        extra = "allow"
