from pydantic import BaseModel


class AdminLockoutThresholdCountInput(BaseModel):
    """Input schema for the adminLockoutThresholdCount transformation."""

    class Config:
        extra = "allow"
