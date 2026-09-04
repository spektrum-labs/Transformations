from pydantic import BaseModel


class OpenSecretScanningAlertsCountInput(BaseModel):
    """Input schema for the openSecretScanningAlertsCount transformation."""

    class Config:
        extra = "allow"
