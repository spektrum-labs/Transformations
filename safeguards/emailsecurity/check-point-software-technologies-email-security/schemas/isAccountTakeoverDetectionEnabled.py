from pydantic import BaseModel


class IsAccountTakeoverDetectionEnabledInput(BaseModel):
    """Input schema for the isAccountTakeoverDetectionEnabled transformation."""

    class Config:
        extra = "allow"
