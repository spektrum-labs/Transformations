from pydantic import BaseModel


class IsThirdPartyPatchManagementEnabledInput(BaseModel):
    """Input schema for the isThirdPartyPatchManagementEnabled transformation."""

    class Config:
        extra = "allow"
