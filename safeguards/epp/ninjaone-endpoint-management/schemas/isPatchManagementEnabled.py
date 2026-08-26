from pydantic import BaseModel


class IsPatchManagementEnabledInput(BaseModel):
    """Input schema for the isPatchManagementEnabled transformation.

    Expects the getOSPatchInstallsReport response shape:
    {"cursor": [...], "results": [{"id": ..., "name": ..., "status": ..., "installedAt": ...,
    "deviceId": ..., "kbNumber": ..., "severity": ..., "type": ...}, ...]}
    """

    class Config:
        extra = "allow"
