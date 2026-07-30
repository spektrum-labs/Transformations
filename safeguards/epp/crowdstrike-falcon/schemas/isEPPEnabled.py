from pydantic import BaseModel


class IsEPPEnabledInput(BaseModel):
    """Input schema for the isEPPEnabled transformation."""

    class Config:
        extra = "allow"
