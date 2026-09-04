from pydantic import BaseModel


class IsPatchManagementValidInput(BaseModel):
    """Input schema for the isPatchManagementValid transformation."""

    class Config:
        extra = "allow"
