from pydantic import BaseModel


class WebAuthnCredentialAdoptionPercentageInput(BaseModel):
    """Input schema for the webAuthnCredentialAdoptionPercentage transformation."""

    class Config:
        extra = "allow"
