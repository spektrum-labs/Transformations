from pydantic import BaseModel


class IsBitLockerRecoveryKeyEscrowedInput(BaseModel):
    """Input schema for the isBitLockerRecoveryKeyEscrowed transformation.

    Accepts the getVolumesReport response shape: an envelope with a
    `results` list of volume records, each optionally carrying a
    `bitLockerStatus` object with protection/escrow indicators.
    """

    class Config:
        extra = "allow"
