from pydantic import BaseModel


class IsRemediationTrackedInput(BaseModel):
    """Input schema for the isRemediationTracked transformation."""

    class Config:
        extra = "allow"
