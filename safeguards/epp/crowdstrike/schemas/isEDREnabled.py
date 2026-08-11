from pydantic import BaseModel


class IsEDREnabledInput(BaseModel):
    """Input schema for the isEDREnabled transformation."""

    class Config:
        extra = "allow"
