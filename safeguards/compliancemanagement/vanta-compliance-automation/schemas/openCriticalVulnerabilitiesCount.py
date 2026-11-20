from pydantic import BaseModel


class OpenCriticalVulnerabilitiesCountInput(BaseModel):
    """Input schema for the openCriticalVulnerabilitiesCount transformation."""

    class Config:
        extra = "allow"
