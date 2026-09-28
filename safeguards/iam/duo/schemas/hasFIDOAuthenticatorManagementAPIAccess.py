from pydantic import BaseModel


class HasFIDOAuthenticatorManagementAPIAccessInput(BaseModel):
    """Input schema for the hasFIDOAuthenticatorManagementAPIAccess transformation."""

    class Config:
        extra = "allow"
