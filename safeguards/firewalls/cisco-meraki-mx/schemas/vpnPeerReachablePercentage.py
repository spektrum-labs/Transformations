from pydantic import BaseModel


class VpnPeerReachablePercentageInput(BaseModel):
    """Input schema for the vpnPeerReachablePercentage transformation."""

    class Config:
        extra = "allow"
