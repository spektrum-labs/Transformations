from pydantic import BaseModel


class OldestOpenCriticalInvestigationAgeDaysCountInput(BaseModel):
    """Input schema for the oldestOpenCriticalInvestigationAgeDaysCount transformation."""

    class Config:
        extra = "allow"
