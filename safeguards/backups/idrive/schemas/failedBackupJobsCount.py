from pydantic import BaseModel


class FailedBackupJobsCountInput(BaseModel):
    """Input schema for the failedBackupJobsCount transformation."""

    class Config:
        extra = "allow"
