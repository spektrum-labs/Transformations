from pydantic import BaseModel


class IsQuarantineRestoreWorkflowAutomatedInput(BaseModel):
    """Input schema for the isQuarantineRestoreWorkflowAutomated transformation."""

    class Config:
        extra = "allow"
