from pydantic import BaseModel


class VaultRegionCountInput(BaseModel):
    """Input schema for the vaultRegionCount transformation."""

    class Config:
        extra = "allow"
