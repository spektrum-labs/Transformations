from pydantic import BaseModel


class IsUsageAnalyticsExportEnabledInput(BaseModel):
    """Input schema for the isUsageAnalyticsExportEnabled transformation."""

    class Config:
        extra = "allow"
