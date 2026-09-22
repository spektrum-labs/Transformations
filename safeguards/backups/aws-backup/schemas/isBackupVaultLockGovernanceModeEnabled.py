from pydantic import BaseModel


class IsBackupVaultLockGovernanceModeEnabledInput(BaseModel):
    """Input schema for the isBackupVaultLockGovernanceModeEnabled transformation."""

    class Config:
        extra = "allow"
