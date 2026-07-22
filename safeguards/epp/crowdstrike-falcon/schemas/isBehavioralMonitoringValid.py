from pydantic import BaseModel


class IsBehavioralMonitoringValidInput(BaseModel):
    """Input schema for the isBehavioralMonitoringValid transformation."""

    class Config:
        extra = "allow"
