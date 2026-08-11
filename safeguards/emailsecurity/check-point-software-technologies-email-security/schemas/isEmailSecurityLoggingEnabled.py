from pydantic import BaseModel


class IsEmailSecurityLoggingEnabledInput(BaseModel):
    """Input schema for the isEmailSecurityLoggingEnabled transformation."""

    class Config:
        extra = "allow"
