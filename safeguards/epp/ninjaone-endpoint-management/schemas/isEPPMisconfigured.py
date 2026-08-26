from pydantic import BaseModel


class IsEPPMisconfiguredInput(BaseModel):
    """Input schema for the isEPPMisconfigured transformation.

    Accepts the raw or enriched getAntivirusStatusReport response:
    {"cursor": ..., "results": [{"productName": str, "productState": str,
    "definitionStatus": str, "version": str, "deviceId": int, "timestamp": float}, ...]}
    """

    class Config:
        extra = "allow"
