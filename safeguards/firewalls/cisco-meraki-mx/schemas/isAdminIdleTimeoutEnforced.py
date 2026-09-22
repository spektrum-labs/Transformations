from pydantic import BaseModel


class IsAdminIdleTimeoutEnforcedInput(BaseModel):
    """Input schema for the isAdminIdleTimeoutEnforced transformation."""

    class Config:
        extra = "allow"
