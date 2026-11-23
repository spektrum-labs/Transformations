from pydantic import BaseModel


class IsRealTimeProtectionEnabledInput(BaseModel):
    """Input schema for the isRealTimeProtectionEnabled transformation."""

    class Config:
        extra = "allow"
