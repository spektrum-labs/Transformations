from pydantic import BaseModel


class IncidentAnalystAssignmentPercentageInput(BaseModel):
    """Input schema for the incidentAnalystAssignmentPercentage transformation."""

    class Config:
        extra = "allow"
