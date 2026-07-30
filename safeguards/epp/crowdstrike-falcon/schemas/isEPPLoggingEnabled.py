from pydantic import BaseModel


class IsEPPLoggingEnabledInput(BaseModel):
    """Input schema for the isEPPLoggingEnabled transformation."""

    class Config:
        extra = "allow"
