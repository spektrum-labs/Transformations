from pydantic import BaseModel
from typing import Optional


class IsStrongPasswordPolicyEnforcedInput(BaseModel):
    """Input schema for the isStrongPasswordPolicyEnforced transformation."""
    enforceStrongPasswords: Optional[bool] = None
    minimumPasswordLength: Optional[int] = None

    class Config:
        extra = "allow"
