from pydantic import BaseModel


class ScanFailureCountInput(BaseModel):
    """Input schema for the scanFailureCount transformation.

    Expects the getOSPatchesReport response shape:
    {"cursor": [...], "results": [{"id":..., "name":..., "status": "FAILED"|"PENDING"|"REJECTED", "deviceId":..., ...}]}
    """

    class Config:
        extra = "allow"
