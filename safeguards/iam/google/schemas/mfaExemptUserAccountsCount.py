from pydantic import BaseModel


class MfaExemptUserAccountsCountInput(BaseModel):
    """Input schema for the mfaExemptUserAccountsCount transformation."""

    class Config:
        extra = "allow"
