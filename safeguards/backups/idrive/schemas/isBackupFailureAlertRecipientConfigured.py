from pydantic import BaseModel


class IsBackupFailureAlertRecipientConfiguredInput(BaseModel):
    """Input schema for the isBackupFailureAlertRecipientConfigured transformation."""

    class Config:
        extra = "allow"
