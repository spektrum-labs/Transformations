from pydantic import BaseModel


class StaleSensorCountInput(BaseModel):
    """Input schema for the staleSensorCount transformation.

    Accepts the getDevicesDetailed response shape: either a bare list of
    device records (array root) or an enveloped {"data": [...]} payload.
    Each device record is expected to carry a lastContact epoch timestamp
    used to determine staleness against a 14-day threshold.
    """

    class Config:
        extra = "allow"
