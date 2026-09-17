from pydantic import BaseModel


class IsSecretScanningPushProtectionEnabledInput(BaseModel):
    """Input schema for the isSecretScanningPushProtectionEnabled transformation."""

    class Config:
        extra = "allow"
