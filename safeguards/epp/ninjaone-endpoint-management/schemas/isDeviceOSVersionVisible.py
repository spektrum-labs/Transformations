from pydantic import BaseModel


class IsDeviceOSVersionVisibleInput(BaseModel):
    """Input schema for the isDeviceOSVersionVisible transformation."""

    class Config:
        extra = "allow"
