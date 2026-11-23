from pydantic import BaseModel


class StaleProtectionJobsCountInput(BaseModel):
    """Input schema for the staleProtectionJobsCount transformation."""

    class Config:
        extra = "allow"
