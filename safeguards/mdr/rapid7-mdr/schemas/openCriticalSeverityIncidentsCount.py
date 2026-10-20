from pydantic import BaseModel


class OpenCriticalSeverityIncidentsCountInput(BaseModel):
    """Input schema for the openCriticalSeverityIncidentsCount transformation."""

    class Config:
        extra = "allow"
