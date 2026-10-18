from pydantic import BaseModel


class IsSmsAuthenticationDisabledInput(BaseModel):
    """Input schema for the isSmsAuthenticationDisabled transformation."""

    class Config:
        extra = "allow"
