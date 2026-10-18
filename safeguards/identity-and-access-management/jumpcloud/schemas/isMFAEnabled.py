from pydantic import BaseModel


class IsMFAEnabledInput(BaseModel):
    """Input schema for the isMFAEnabled transformation."""

    class Config:
        extra = "allow"
