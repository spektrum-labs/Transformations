from pydantic import BaseModel


class BackupSlaComplianceRatePercentageInput(BaseModel):
    """Input schema for the backupSlaComplianceRatePercentage transformation."""

    class Config:
        extra = "allow"
