from pydantic import BaseModel


class IsBitLockerRecoveryKeyEscrowedInput(BaseModel):
    """Input schema for the isBitLockerRecoveryKeyEscrowed transformation."""

    class Config:
        extra = "allow"
