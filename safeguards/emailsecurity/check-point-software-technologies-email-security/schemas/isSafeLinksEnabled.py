from pydantic import BaseModel


class IsSafeLinksEnabledInput(BaseModel):
    """Input schema for the isSafeLinksEnabled transformation."""

    class Config:
        extra = "allow"
