from pydantic import BaseModel


class IsPatchManagementEnabledInput(BaseModel):
    """Input schema for the isPatchManagementEnabled transformation.

    Expects the raw or enriched response from NinjaOne's /v2/policies
    endpoint: either a bare list of policy objects, or an envelope dict
    wrapping that list under 'data'/'results'/'policies'. Kept permissive
    since the vendor may add fields without notice.
    """

    class Config:
        extra = "allow"
