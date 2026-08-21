from pydantic import BaseModel


class IsDeviceAutoApprovalDisabledInput(BaseModel):
    """Input schema for the isDeviceAutoApprovalDisabled transformation."""

    class Config:
        extra = "allow"
