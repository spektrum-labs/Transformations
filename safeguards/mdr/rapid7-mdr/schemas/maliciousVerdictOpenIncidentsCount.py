from pydantic import BaseModel


class MaliciousVerdictOpenIncidentsCountInput(BaseModel):
    """Input schema for the maliciousVerdictOpenIncidentsCount transformation."""

    class Config:
        extra = "allow"
