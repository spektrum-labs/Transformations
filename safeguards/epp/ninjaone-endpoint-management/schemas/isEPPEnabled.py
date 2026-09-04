from pydantic import BaseModel


class IsEPPEnabledInput(BaseModel):
    """Input schema for the isEPPEnabled transformation.

    Accepts the antivirus-status report response, either the raw
    {"cursor": ..., "results": [...]} envelope or the enriched
    {"data": ..., "validation": ...} wrapper. Kept permissive since
    vendor rows may carry additional fields not enumerated here.
    """

    class Config:
        extra = "allow"
