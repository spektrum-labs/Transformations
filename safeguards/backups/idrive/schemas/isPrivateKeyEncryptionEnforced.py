from pydantic import BaseModel


class IsPrivateKeyEncryptionEnforcedInput(BaseModel):
    """Input schema for the isPrivateKeyEncryptionEnforced transformation."""

    class Config:
        extra = "allow"
