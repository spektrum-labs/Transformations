from pydantic import BaseModel


class IsAgentDeployedInput(BaseModel):
    """Input schema for the isAgentDeployed transformation.

    Expects the getDevicesDetailed response: either a raw list of device
    records or an envelope dict wrapping them (e.g. under 'data'). Each
    device record is expected to carry 'approvalStatus' and 'offline'
    fields, per the captured NinjaOne /v2/devices-detailed response.
    """

    class Config:
        extra = "allow"
