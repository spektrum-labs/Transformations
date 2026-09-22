from pydantic import BaseModel


class OpenCriticalDependabotAlertsCountInput(BaseModel):
    """Input schema for the openCriticalDependabotAlertsCount transformation."""

    class Config:
        extra = "allow"
