from pydantic import BaseModel


class IsFlexibleSecurityEventQueryEnabledInput(BaseModel):
    """Input schema for the isFlexibleSecurityEventQueryEnabled transformation."""

    class Config:
        extra = "allow"
