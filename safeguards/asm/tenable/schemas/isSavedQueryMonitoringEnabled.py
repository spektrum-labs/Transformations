from pydantic import BaseModel


class IsSavedQueryMonitoringEnabledInput(BaseModel):
    """Input schema for the isSavedQueryMonitoringEnabled transformation."""

    class Config:
        extra = "allow"
