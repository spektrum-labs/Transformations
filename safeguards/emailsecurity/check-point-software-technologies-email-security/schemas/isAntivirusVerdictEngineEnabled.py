from pydantic import BaseModel


class IsAntivirusVerdictEngineEnabledInput(BaseModel):
    """Input schema for the isAntivirusVerdictEngineEnabled transformation."""

    class Config:
        extra = "allow"
