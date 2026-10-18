from pydantic import BaseModel


class IsEncryptionRequiredFlagSetInput(BaseModel):
    """Input schema for the isEncryptionRequiredFlagSet transformation."""

    class Config:
        extra = "allow"
