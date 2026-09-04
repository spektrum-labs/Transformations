from pydantic import BaseModel


class OpenHighSeverityVulnerabilitiesCountInput(BaseModel):
    """Input schema for the openHighSeverityVulnerabilitiesCount transformation."""

    class Config:
        extra = "allow"
