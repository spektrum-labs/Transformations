from pydantic import BaseModel


class PendingOrgInvitesCountInput(BaseModel):
    """Input schema for the pendingOrgInvitesCount transformation."""

    class Config:
        extra = "allow"
