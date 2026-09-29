from pydantic import BaseModel


class HasAuthenticationLogAPIAccessInput(BaseModel):
    """Input schema for the hasAuthenticationLogAPIAccess transformation."""

    class Config:
        extra = "allow"
