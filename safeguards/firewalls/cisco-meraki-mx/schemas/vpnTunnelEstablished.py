from pydantic import BaseModel


class VpnTunnelEstablishedInput(BaseModel):
    """Input schema for the vpnTunnelEstablished transformation."""

    class Config:
        extra = "allow"
