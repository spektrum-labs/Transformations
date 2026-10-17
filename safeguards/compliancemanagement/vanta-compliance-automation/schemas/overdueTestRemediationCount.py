from pydantic import BaseModel


class OverdueTestRemediationCountInput(BaseModel):
    """Input schema for the overdueTestRemediationCount transformation."""

    class Config:
        extra = "allow"
