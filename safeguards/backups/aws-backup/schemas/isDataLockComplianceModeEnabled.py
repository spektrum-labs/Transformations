from pydantic import BaseModel


class IsDataLockComplianceModeEnabledInput(BaseModel):
    """Input schema for the isDataLockComplianceModeEnabled transformation."""

    class Config:
        extra = "allow"
