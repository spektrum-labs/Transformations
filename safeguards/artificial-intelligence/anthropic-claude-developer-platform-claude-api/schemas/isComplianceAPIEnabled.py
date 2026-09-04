from pydantic import BaseModel


class IsComplianceAPIEnabledInput(BaseModel):
    """Input schema for the isComplianceAPIEnabled transformation."""

    class Config:
        extra = "allow"
