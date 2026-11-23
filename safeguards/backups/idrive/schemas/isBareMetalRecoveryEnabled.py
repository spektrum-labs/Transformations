from pydantic import BaseModel


class IsBareMetalRecoveryEnabledInput(BaseModel):
    """Input schema for the isBareMetalRecoveryEnabled transformation."""

    class Config:
        extra = "allow"
