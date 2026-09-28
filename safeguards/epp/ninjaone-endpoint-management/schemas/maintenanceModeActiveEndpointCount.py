from pydantic import BaseModel


class MaintenanceModeActiveEndpointCountInput(BaseModel):
    """Input schema for the maintenanceModeActiveEndpointCount transformation."""

    class Config:
        extra = "allow"
