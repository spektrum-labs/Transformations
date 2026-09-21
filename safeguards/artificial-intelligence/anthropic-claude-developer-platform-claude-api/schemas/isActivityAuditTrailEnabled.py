from pydantic import BaseModel


class IsActivityAuditTrailEnabledInput(BaseModel):
    """Input schema for the isActivityAuditTrailEnabled transformation."""

    class Config:
        extra = "allow"
