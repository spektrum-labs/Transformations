from pydantic import BaseModel


class IsFactSheetAPIKeyRotationEnabledInput(BaseModel):
    """Input schema for the isFactSheetAPIKeyRotationEnabled transformation."""

    class Config:
        extra = "allow"
