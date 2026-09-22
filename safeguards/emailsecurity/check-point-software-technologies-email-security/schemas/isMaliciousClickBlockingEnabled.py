from pydantic import BaseModel


class IsMaliciousClickBlockingEnabledInput(BaseModel):
    """Input schema for the isMaliciousClickBlockingEnabled transformation."""

    class Config:
        extra = "allow"
