from pydantic import BaseModel


class StaleServiceAccountsCountInput(BaseModel):
    """Input schema for the staleServiceAccountsCount transformation."""

    class Config:
        extra = "allow"
