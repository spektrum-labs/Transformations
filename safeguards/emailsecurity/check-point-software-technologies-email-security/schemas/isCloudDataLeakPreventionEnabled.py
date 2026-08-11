from pydantic import BaseModel


class IsCloudDataLeakPreventionEnabledInput(BaseModel):
    """Input schema for the isCloudDataLeakPreventionEnabled transformation."""

    class Config:
        extra = "allow"
