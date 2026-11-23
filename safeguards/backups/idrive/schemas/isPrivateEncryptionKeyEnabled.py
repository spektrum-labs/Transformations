from pydantic import BaseModel

class IsPrivateEncryptionKeyEnabledInput(BaseModel):
    """Input schema for the isPrivateEncryptionKeyEnabled transformation."""
    class Config:
        extra = "allow"
