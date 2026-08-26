from pydantic import BaseModel


class IsEDRDeployedInput(BaseModel):
    """Input schema for the isEDRDeployed transformation.

    Expected shape (from getAntivirusStatusReport /v2/queries/antivirus-status):
    {
        "cursor": [...],
        "results": [
            {
                "productName": "CrowdStrike Falcon Sensor",
                "productState": "ON",
                "definitionStatus": "Up-to-Date",
                "version": "7.39.21108.0",
                "deviceId": 385,
                "timestamp": 1787702109.0
            },
            ...
        ]
    }
    """

    class Config:
        extra = "allow"
