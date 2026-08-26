from pydantic import BaseModel


class IsMaintenanceModeTimeLimitedInput(BaseModel):
    """Input schema for the isMaintenanceModeTimeLimited transformation."""

    class Config:
        extra = "allow"
