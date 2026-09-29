from pydantic import BaseModel


class IsLifeCycleManagementEnabledInput(BaseModel):
    """Input schema for the isLifeCycleManagementEnabled transformation."""

    class Config:
        extra = "allow"
