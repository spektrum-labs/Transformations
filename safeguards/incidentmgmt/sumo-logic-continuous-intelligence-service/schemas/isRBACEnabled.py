from pydantic import BaseModel


class IsRBACEnabledInput(BaseModel):
    """Input schema for the isRBACEnabled transformation."""

    class Config:
        extra = "allow"
