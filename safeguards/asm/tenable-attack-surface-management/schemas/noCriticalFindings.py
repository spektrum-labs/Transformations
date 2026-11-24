from pydantic import BaseModel


class NoCriticalFindingsInput(BaseModel):
    """Input schema for the noCriticalFindings transformation."""

    class Config:
        extra = "allow"
