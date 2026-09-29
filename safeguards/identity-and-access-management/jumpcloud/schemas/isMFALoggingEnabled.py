from pydantic import BaseModel


class IsMFALoggingEnabledInput(BaseModel):
    """Input schema for the isMFALoggingEnabled transformation."""

    class Config:
        extra = "allow"
