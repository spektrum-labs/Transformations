from pydantic import BaseModel


class IsComplianceExportEnabledInput(BaseModel):
    """Input schema for the isComplianceExportEnabled transformation."""

    class Config:
        extra = "allow"
