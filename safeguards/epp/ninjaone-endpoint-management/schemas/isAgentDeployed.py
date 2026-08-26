from pydantic import BaseModel


class IsAgentDeployedInput(BaseModel):
    """Input schema for the isAgentDeployed transformation.

    Accepts the raw or enriched getDevicesDetailed response: a bare
    array of device records (each with approvalStatus, offline,
    lastContact, systemName, etc.) or an envelope wrapping that array.
    """

    class Config:
        extra = "allow"
