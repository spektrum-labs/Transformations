from pydantic import BaseModel


class InactiveMfaFactorsCountInput(BaseModel):
    """Input schema for the inactiveMfaFactorsCount transformation."""

    class Config:
        extra = "allow"
