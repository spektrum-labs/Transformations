from pydantic import BaseModel


class NoHighFindingsInput(BaseModel):
    """Input schema for the noHighFindings transformation."""

    class Config:
        extra = "allow"
