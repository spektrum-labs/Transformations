from pydantic import BaseModel


class StaleSensorCountInput(BaseModel):
    """Input schema for the staleSensorCount transformation."""

    class Config:
        extra = "allow"
