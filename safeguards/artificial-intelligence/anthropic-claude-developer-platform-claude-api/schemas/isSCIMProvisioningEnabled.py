from pydantic import BaseModel


class IsSCIMProvisioningEnabledInput(BaseModel):
    """Input schema for the isSCIMProvisioningEnabled transformation."""

    class Config:
        extra = "allow"
