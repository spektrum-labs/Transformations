from pydantic import BaseModel


class IsCloudDataLeakPreventionEnabledInput(BaseModel):
    """Input schema for the isCloudDataLeakPreventionEnabled transformation.

    Expects the queryEvents API response shape:
    {
        "responseEnvelope": {"totalRecordsNumber": int, "scrollId": str, ...},
        "responseData": [
            {
                "eventId": str,
                "type": str,          # e.g. 'dlp'
                "description": str,   # e.g. 'DLP Engine has detected a leak...'
                ...
            },
            ...
        ]
    }
    """

    class Config:
        extra = "allow"
