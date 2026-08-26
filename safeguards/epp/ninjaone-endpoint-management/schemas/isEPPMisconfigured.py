from pydantic import BaseModel
from typing import Any, Optional


class IsEPPMisconfiguredInput(BaseModel):
    """Input schema for the isEPPMisconfigured transformation.

    Expects the getAntivirusStatusReport payload:
    {
      "cursor": [...],
      "results": [
        {
          "productName": str,
          "productState": str,   # e.g. ON, OFF, SNOOZED
          "definitionStatus": str,  # e.g. Up-to-Date
          "version": str,
          "deviceId": int,
          "timestamp": float
        },
        ...
      ]
    }
    """
    cursor: Optional[Any] = None
    results: Optional[Any] = None

    class Config:
        extra = "allow"
