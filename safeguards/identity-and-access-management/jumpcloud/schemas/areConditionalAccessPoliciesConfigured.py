from pydantic import BaseModel

class AreConditionalAccessPoliciesConfiguredInput(BaseModel):
    """Input schema for the areConditionalAccessPoliciesConfigured transformation."""
    class Config:
        extra = "allow"
