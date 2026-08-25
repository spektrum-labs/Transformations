from pydantic import BaseModel


class PendingApprovalRequestCountInput(BaseModel):
    """Input schema for the pendingApprovalRequestCount transformation."""

    class Config:
        extra = "allow"
