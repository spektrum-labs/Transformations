from pydantic import BaseModel


class IsDeviceOfflineAlertingEnabledInput(BaseModel):
    """Input schema for the isDeviceOfflineAlertingEnabled transformation."""

    class Config:
        extra = "allow"
