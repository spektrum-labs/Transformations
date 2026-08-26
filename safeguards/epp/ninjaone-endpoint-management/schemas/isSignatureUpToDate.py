from pydantic import BaseModel


class IsSignatureUpToDateInput(BaseModel):
    """Input schema for the isSignatureUpToDate transformation."""

    class Config:
        extra = "allow"
