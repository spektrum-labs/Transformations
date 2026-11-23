from pydantic import BaseModel


class IsAPIAccountPermissionScopedInput(BaseModel):
    """Input schema for the isAPIAccountPermissionScoped transformation."""

    class Config:
        extra = "allow"
