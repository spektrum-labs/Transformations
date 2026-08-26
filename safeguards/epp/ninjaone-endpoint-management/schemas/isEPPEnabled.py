from pydantic import BaseModel
from typing import Optional, List, Any


class IsEPPEnabledInput(BaseModel):
    """Input schema for the isEPPEnabled transformation.

    Expects the getAntivirusStatusReport response shape:
    {"cursor": [...], "results": [{"productName": str, "productState": str,
     "definitionStatus": str, "version": str, "deviceId": int, "timestamp": float}, ...]}
    Also tolerant of a raw list of such records or the enriched
    {"data": ..., "validation": ...} envelope.
    """

    class Config:
        extra = "allow"
