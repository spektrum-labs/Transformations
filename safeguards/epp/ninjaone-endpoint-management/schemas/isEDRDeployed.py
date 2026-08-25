from pydantic import BaseModel


class IsEDRDeployedInput(BaseModel):
    """Input schema for the isEDRDeployed transformation.

    Expects the NinjaOne getAntivirusStatus response shape:
    {"cursor": {...}, "results": [{"productName": str, "productState": str,
    "definitionStatus": str, "version": str, "deviceId": int, "timestamp": float}, ...]}
    """

    class Config:
        extra = "allow"
