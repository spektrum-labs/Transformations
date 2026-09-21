from pydantic import BaseModel


class IsPermissionGroupScopedAPIAccessEnforcedInput(BaseModel):
    """Input schema for the isPermissionGroupScopedAPIAccessEnforced transformation."""

    class Config:
        extra = "allow"
