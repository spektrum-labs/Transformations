from pydantic import BaseModel


class OpenCriticalSeverityAlertsCountInput(BaseModel):
    """Input schema for the openCriticalSeverityAlertsCount transformation."""

    class Config:
        extra = "allow"
