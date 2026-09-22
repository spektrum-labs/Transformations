from pydantic import BaseModel


class IsGroupBasedAccessControlEnabledInput(BaseModel):
    """Input schema for the isGroupBasedAccessControlEnabled transformation."""

    class Config:
        extra = "allow"
