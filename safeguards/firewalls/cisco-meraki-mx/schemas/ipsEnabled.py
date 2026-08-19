from pydantic import BaseModel


class IpsEnabledInput(BaseModel):
    """Input schema for the ipsEnabled transformation."""

    class Config:
        extra = "allow"
