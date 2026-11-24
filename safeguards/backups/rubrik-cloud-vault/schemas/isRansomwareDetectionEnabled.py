from pydantic import BaseModel


class IsRansomwareDetectionEnabledInput(BaseModel):
    """Input schema for the isRansomwareDetectionEnabled transformation."""

    class Config:
        extra = "allow"
