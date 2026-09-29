from pydantic import BaseModel


class IsIAMLoggingEnabledInput(BaseModel):
    """Input schema for the isIAMLoggingEnabled transformation."""

    class Config:
        extra = "allow"
