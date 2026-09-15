from pydantic import BaseModel


class MessageMoveAuditTrailEnabledInput(BaseModel):
    """Input schema for the messageMoveAuditTrailEnabled transformation."""

    class Config:
        extra = "allow"
