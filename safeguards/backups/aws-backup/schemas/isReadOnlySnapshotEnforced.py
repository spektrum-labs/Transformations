from pydantic import BaseModel


class IsReadOnlySnapshotEnforcedInput(BaseModel):
    """Input schema for the isReadOnlySnapshotEnforced transformation."""

    class Config:
        extra = "allow"
