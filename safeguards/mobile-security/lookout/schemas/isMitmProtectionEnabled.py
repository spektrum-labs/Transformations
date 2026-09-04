from pydantic import BaseModel


class IsMitmProtectionEnabledInput(BaseModel):
    """Input schema for the isMitmProtectionEnabled transformation."""

    class Config:
        extra = "allow"
