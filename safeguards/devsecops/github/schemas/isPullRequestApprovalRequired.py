from pydantic import BaseModel


class IsPullRequestApprovalRequiredInput(BaseModel):
    """Input schema for the isPullRequestApprovalRequired transformation."""

    class Config:
        extra = "allow"
