from pydantic import BaseModel


class IsSubdomainTakeoverDetectedInput(BaseModel):
    """Input schema for the isSubdomainTakeoverDetected transformation."""

    class Config:
        extra = "allow"
