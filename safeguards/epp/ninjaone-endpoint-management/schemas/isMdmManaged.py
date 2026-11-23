from pydantic import BaseModel


class IsMdmManagedInput(BaseModel):
    """Input schema for the isMdmManaged transformation."""

    class Config:
        extra = "allow"
