from pydantic import BaseModel


class IsEPPConfiguredInput(BaseModel):
    """Input schema for the isEPPConfigured transformation.

    Accepts the raw or enriched getAntivirusStatusReport response, whose
    payload is either a dict envelope with a `results` list of per-device
    antivirus status records, or the unwrapped list itself.
    """

    class Config:
        extra = "allow"
