from pydantic import BaseModel


class IsBackupClientVersionCurrentInput(BaseModel):
    """Input schema for the isBackupClientVersionCurrent transformation."""

    class Config:
        extra = "allow"
