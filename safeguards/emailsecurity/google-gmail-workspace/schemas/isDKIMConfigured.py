from pydantic import BaseModel


class IsDKIMConfiguredInput(BaseModel):
    """Input schema for the isDKIMConfigured transformation."""

    class Config:
        extra = "allow"
