from pydantic import BaseModel


class WorkspaceUserMfaEnrollmentPercentageInput(BaseModel):
    """Input schema for the workspaceUserMfaEnrollmentPercentage transformation."""

    class Config:
        extra = "allow"
