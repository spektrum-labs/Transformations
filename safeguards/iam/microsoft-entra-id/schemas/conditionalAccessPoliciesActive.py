from pydantic import BaseModel


class ConditionalAccessPoliciesActiveInput(BaseModel):
    """Input schema for the conditionalAccessPoliciesActive transformation."""

    class Config:
        extra = "allow"
