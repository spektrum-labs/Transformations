from pydantic import BaseModel

class IsRBACEnforcedInput(BaseModel):
    """Input schema for the isRBACEnforced transformation."""
    class Config:
        extra = "allow"
