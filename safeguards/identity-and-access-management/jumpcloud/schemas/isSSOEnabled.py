from pydantic import BaseModel


class IsSSOEnabledInput(BaseModel):
    """Input schema for the isSSOEnabled transformation."""

    class Config:
        extra = "allow"
