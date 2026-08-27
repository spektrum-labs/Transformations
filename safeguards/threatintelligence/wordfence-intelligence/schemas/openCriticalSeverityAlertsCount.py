from pydantic import BaseModel


class OpenCriticalSeverityAlertsCountInput(BaseModel):
    """Input schema for the openCriticalSeverityAlertsCount transformation.

    Accepts the raw Wordfence Intelligence production vulnerability feed
    response (a dict keyed by vulnerability UUID, each value containing at
    minimum id, title, software, cvss, informational fields), or the
    runtime-enriched {data, validation} envelope wrapping it.
    """

    class Config:
        extra = "allow"
