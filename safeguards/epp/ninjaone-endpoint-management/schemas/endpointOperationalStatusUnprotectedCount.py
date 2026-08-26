from pydantic import BaseModel


class EndpointOperationalStatusUnprotectedCountInput(BaseModel):
    """Input schema for the endpointOperationalStatusUnprotectedCount transformation."""

    class Config:
        extra = "allow"
