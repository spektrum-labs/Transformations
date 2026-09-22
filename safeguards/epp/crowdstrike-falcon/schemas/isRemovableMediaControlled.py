from pydantic import BaseModel


class IsRemovableMediaControlledInput(BaseModel):
    """Input schema for the isRemovableMediaControlled transformation."""

    class Config:
        extra = "allow"
