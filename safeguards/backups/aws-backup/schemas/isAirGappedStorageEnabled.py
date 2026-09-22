from pydantic import BaseModel


class IsAirGappedStorageEnabledInput(BaseModel):
    """Input schema for the isAirGappedStorageEnabled transformation."""

    class Config:
        extra = "allow"
