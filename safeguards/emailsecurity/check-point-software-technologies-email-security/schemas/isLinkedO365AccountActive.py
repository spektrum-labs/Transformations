from pydantic import BaseModel


class IsLinkedO365AccountActiveInput(BaseModel):
    """Input schema for the isLinkedO365AccountActive transformation."""

    class Config:
        extra = "allow"
