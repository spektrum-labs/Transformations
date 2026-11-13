from pydantic import BaseModel


class IsASMEnabledInput(BaseModel):
    """Input schema for the isASMEnabled transformation."""

    class Config:
        extra = "allow"
