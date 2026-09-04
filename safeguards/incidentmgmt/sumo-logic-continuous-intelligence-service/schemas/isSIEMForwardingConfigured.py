from pydantic import BaseModel


class IsSIEMForwardingConfiguredInput(BaseModel):
    """Input schema for the isSIEMForwardingConfigured transformation."""

    class Config:
        extra = "allow"
