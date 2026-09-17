from pydantic import BaseModel


class IsModelInventoryTrackingEnforcedInput(BaseModel):
    """Input schema for the isModelInventoryTrackingEnforced transformation."""

    class Config:
        extra = "allow"
