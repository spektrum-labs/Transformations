from pydantic import BaseModel


class IsBackupEncryptedInput(BaseModel):
    """Input schema for the isBackupEncrypted transformation."""

    class Config:
        extra = "allow"
