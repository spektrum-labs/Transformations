from pydantic import BaseModel


class IsAuditLoggingEnabledInput(BaseModel):
    """Input schema for the isAuditLoggingEnabled transformation."""

    class Config:
        extra = "allow"
