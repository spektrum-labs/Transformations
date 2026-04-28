from pydantic import BaseModel


class ConfirmedLicensePurchasedOutput(BaseModel):
    confirmedLicensePurchased: bool
