from pydantic import BaseModel


class UnverifiedAllowPolicyCountInput(BaseModel):
    """Input schema for the unverifiedAllowPolicyCount transformation."""

    class Config:
        extra = "allow"
