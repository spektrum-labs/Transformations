from pydantic import BaseModel


class IsSingleActionMultiEntityRemediationEnabledInput(BaseModel):
    """Input schema for the isSingleActionMultiEntityRemediationEnabled transformation."""

    class Config:
        extra = "allow"
