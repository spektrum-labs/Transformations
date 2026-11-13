from pydantic import BaseModel


class FailingMonitoringTestsCountInput(BaseModel):
    """Input schema for the failingMonitoringTestsCount transformation."""

    class Config:
        extra = "allow"
