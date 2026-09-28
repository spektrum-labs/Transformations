from pydantic import BaseModel

class PolicyOverrideDriftCountInput(BaseModel):
    """Input schema for the policyOverrideDriftCount transformation."""
    class Config:
        extra = "allow"
