from pydantic import BaseModel


class IsEmailLoggingEnabledInput(BaseModel):
    """Input schema for the isEmailLoggingEnabled transformation."""

    class Config:
        extra = "allow"
