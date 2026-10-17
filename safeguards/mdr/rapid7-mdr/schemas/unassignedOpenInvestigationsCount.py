from pydantic import BaseModel


class UnassignedOpenInvestigationsCountInput(BaseModel):
    """Input schema for the unassignedOpenInvestigationsCount transformation."""

    class Config:
        extra = "allow"
