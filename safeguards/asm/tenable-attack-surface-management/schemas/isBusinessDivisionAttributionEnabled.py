from pydantic import BaseModel


class IsBusinessDivisionAttributionEnabledInput(BaseModel):
    """Input schema for the isBusinessDivisionAttributionEnabled transformation."""

    class Config:
        extra = "allow"
