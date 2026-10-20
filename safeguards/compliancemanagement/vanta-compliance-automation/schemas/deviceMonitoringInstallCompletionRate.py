from pydantic import BaseModel


class DeviceMonitoringInstallCompletionRateInput(BaseModel):
    """Input schema for the deviceMonitoringInstallCompletionRate transformation."""

    class Config:
        extra = "allow"
