from pydantic import BaseModel


class IsDesktopAppStatusRestrictedInput(BaseModel):
    """Input schema for the isDesktopAppStatusRestricted transformation."""

    class Config:
        extra = "allow"
