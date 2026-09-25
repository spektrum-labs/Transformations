from pydantic import BaseModel


class SuperAdminAccountsWithoutMfaCountInput(BaseModel):
    """Input schema for the superAdminAccountsWithoutMfaCount transformation."""

    class Config:
        extra = "allow"
