from pydantic import BaseModel


class IsNonHumanIdentityInventoryEnabledInput(BaseModel):
    """Input schema for the isNonHumanIdentityInventoryEnabled transformation."""

    class Config:
        extra = "allow"
