from pydantic import BaseModel

class WorkspaceUserMfaEnforcementPercentageInput(BaseModel):
    """Input schema for the workspaceUserMfaEnforcementPercentage transformation."""
    class Config:
        extra = "allow"
