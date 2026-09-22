from pydantic import BaseModel


class IsHIPAAReadinessEnabledInput(BaseModel):
    """Input schema for the isHIPAAReadinessEnabled transformation."""

    class Config:
        extra = "allow"
