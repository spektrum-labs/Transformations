from pydantic import BaseModel


class UnprotectedResourcesCountInput(BaseModel):
    """Input schema for the unprotectedResourcesCount transformation."""

    class Config:
        extra = "allow"
