from pydantic import BaseModel


class ConfirmPasswordPolicyEnforcedInput(BaseModel):
    """Input schema for the confirmPasswordPolicyEnforced transformation."""

    class Config:
        extra = "allow"
