from pydantic import BaseModel


class AuthTypesAllowedInput(BaseModel):
    """Input schema for the authTypesAllowed transformation."""

    class Config:
        extra = "allow"
