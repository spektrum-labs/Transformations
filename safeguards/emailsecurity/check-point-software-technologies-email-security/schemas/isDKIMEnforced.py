from pydantic import BaseModel


class IsDKIMEnforcedInput(BaseModel):
    """Input schema for the isDKIMEnforced transformation."""

    class Config:
        extra = "allow"
