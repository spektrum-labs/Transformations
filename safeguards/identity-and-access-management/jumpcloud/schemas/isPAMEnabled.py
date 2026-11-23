from pydantic import BaseModel


class IsPAMEnabledInput(BaseModel):
    """Input schema for the isPAMEnabled transformation."""

    class Config:
        extra = "allow"
