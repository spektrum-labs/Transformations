from pydantic import BaseModel


class IsSubsidiaryDiscoveryEnabledInput(BaseModel):
    """Input schema for the isSubsidiaryDiscoveryEnabled transformation."""

    class Config:
        extra = "allow"
