from pydantic import BaseModel


class ActiveEventSourceCountInput(BaseModel):
    """Input schema for the activeEventSourceCount transformation."""

    class Config:
        extra = "allow"
