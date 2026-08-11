from pydantic import BaseModel


class IsAntiPhishingEnabledInput(BaseModel):
    """Input schema for the isAntiPhishingEnabled transformation."""

    class Config:
        extra = "allow"
