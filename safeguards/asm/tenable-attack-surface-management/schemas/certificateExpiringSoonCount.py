from pydantic import BaseModel


class CertificateExpiringSoonCountInput(BaseModel):
    """Input schema for the certificateExpiringSoonCount transformation."""

    class Config:
        extra = "allow"
