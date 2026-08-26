from pydantic import BaseModel


class PendingApprovalRequestCountInput(BaseModel):
    """Input schema for the pendingApprovalRequestCount transformation.

    Accepts the getDevicesDetailed response - either a raw list of device
    records or an enriched envelope wrapping that list. Kept permissive
    since NinjaOne device records vary in which optional keys are present
    (e.g. `os`, `_truncated`).
    """

    class Config:
        extra = "allow"
