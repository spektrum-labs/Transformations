from pydantic import BaseModel

class IsCodeExecutionNetworkEgressEnabledInput(BaseModel):
    """Input schema for the isCodeExecutionNetworkEgressEnabled transformation."""
    class Config:
        extra = "allow"
