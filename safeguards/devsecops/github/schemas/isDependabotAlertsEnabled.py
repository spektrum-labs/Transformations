from pydantic import BaseModel


class IsDependabotAlertsEnabledInput(BaseModel):
    """Input schema for the isDependabotAlertsEnabled transformation."""

    class Config:
        extra = "allow"
