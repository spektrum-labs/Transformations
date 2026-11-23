from pydantic import BaseModel


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation."""

    class Config:
        extra = "allow"
