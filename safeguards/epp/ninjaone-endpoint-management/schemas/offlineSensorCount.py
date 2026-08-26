from pydantic import BaseModel


class OfflineSensorCountInput(BaseModel):
    """Input schema for the offlineSensorCount transformation."""

    class Config:
        extra = "allow"
