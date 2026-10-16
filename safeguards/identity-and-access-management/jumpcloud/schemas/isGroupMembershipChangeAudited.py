from pydantic import BaseModel


class IsGroupMembershipChangeAuditedInput(BaseModel):
    """Input schema for the isGroupMembershipChangeAudited transformation."""

    class Config:
        extra = "allow"
