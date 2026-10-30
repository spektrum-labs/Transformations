from pydantic import BaseModel


class LegacyAuthBlockedInput(BaseModel):
    """Input schema for the legacyAuthBlocked transformation."""

    class Config:
        extra = "allow"
