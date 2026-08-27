from pydantic import BaseModel


class OpenCriticalSeverityAlertsCountInput(BaseModel):
    """Input schema for the openCriticalSeverityAlertsCount transformation.

    Accepts the Wordfence Production Vulnerability Feed response, which may
    arrive either as a columnar dict of parallel arrays (id, cvss, software,
    ...) or as a list/dict of per-record objects. Kept permissive since the
    exact wrapper/format is not schema-enforced by the vendor.
    """

    class Config:
        extra = "allow"
