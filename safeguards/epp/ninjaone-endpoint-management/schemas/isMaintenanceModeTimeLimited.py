from pydantic import BaseModel


class IsMaintenanceModeTimeLimitedInput(BaseModel):
    """Input schema for the isMaintenanceModeTimeLimited transformation.

    Accepts the getDevicesDetailed response: either a raw list of device
    records or an enriched envelope wrapping that list. Each device record
    may contain a 'maintenance' field (list or dict) with start/end bounds.
    """

    class Config:
        extra = "allow"
