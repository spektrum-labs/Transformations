from pydantic import BaseModel


class ControlReadinessPercentageInput(BaseModel):
    """Input schema for the controlReadinessPercentage transformation."""

    class Config:
        extra = "allow"
