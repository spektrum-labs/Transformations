from pydantic import BaseModel


class IsProtectionPolicyRPOWithinSLAInput(BaseModel):
    """Input schema for the isProtectionPolicyRPOWithinSLA transformation."""

    class Config:
        extra = "allow"
