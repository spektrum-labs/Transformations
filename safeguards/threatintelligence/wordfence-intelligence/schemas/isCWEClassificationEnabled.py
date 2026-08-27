from pydantic import BaseModel


class IsCWEClassificationEnabledInput(BaseModel):
    """Input schema for the isCWEClassificationEnabled transformation."""

    class Config:
        extra = "allow"
