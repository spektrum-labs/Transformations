from pydantic import BaseModel


class IsStrongAuthRequiredInput(BaseModel):
    """Input schema for the isStrongAuthRequired transformation."""

    class Config:
        extra = "allow"
