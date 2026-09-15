from pydantic import BaseModel


class IsPostDeliveryQuarantineEnabledInput(BaseModel):
    """Input schema for the isPostDeliveryQuarantineEnabled transformation."""

    class Config:
        extra = "allow"
