from pydantic import BaseModel


class IsProgrammaticAccessEnabledInput(BaseModel):
    """Input schema for the isProgrammaticAccessEnabled transformation."""

    class Config:
        extra = "allow"
