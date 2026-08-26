from pydantic import BaseModel


class ScanFailureCountInput(BaseModel):
    """Input schema for the scanFailureCount transformation.

    Expects the raw or enriched getOSPatchInstalls response, shaped as
    {"cursor": ..., "results": [{"deviceId": int, "status": str, ...}, ...]}
    or a bare list of such records.
    """

    class Config:
        extra = "allow"
