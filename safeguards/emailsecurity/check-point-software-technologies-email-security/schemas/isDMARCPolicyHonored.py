from pydantic import BaseModel


class IsDMARCPolicyHonoredInput(BaseModel):
    """Input schema for the isDMARCPolicyHonored transformation."""

    class Config:
        extra = "allow"
