from pydantic import BaseModel


class IsVaultManagedKMSEnabledInput(BaseModel):
    """Input schema for the isVaultManagedKMSEnabled transformation."""

    class Config:
        extra = "allow"
