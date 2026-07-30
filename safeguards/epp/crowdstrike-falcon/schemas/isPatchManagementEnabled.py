from pydantic import BaseModel


class IsPatchManagementEnabledInput(BaseModel):
    """Input schema for the isPatchManagementEnabled transformation."""

    class Config:
        extra = "allow"
