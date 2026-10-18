from pydantic import BaseModel


class OverdueCriticalHighVulnerabilitiesCountInput(BaseModel):
    """Input schema for the overdueCriticalHighVulnerabilitiesCount transformation."""

    class Config:
        extra = "allow"
