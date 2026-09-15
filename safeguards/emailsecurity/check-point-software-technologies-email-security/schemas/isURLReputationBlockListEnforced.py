from pydantic import BaseModel


class IsURLReputationBlockListEnforcedInput(BaseModel):
    """Input schema for the isURLReputationBlockListEnforced transformation."""

    class Config:
        extra = "allow"
