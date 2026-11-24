from pydantic import BaseModel


class IsApiAuditLoggingEnabledInput(BaseModel):
    """Input schema for the isApiAuditLoggingEnabled transformation."""

    class Config:
        extra = "allow"
