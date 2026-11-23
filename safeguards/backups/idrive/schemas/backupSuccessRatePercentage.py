from pydantic import BaseModel


class BackupSuccessRatePercentageInput(BaseModel):
    """Input schema for the backupSuccessRatePercentage transformation."""

    class Config:
        extra = "allow"
