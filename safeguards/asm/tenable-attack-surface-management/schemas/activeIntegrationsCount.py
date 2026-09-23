from pydantic import BaseModel


class ActiveIntegrationsCountInput(BaseModel):
    """Input schema for the activeIntegrationsCount transformation."""

    class Config:
        extra = "allow"
