from pydantic import BaseModel


class IsAttachmentSandboxDetonationEnabledInput(BaseModel):
    """Input schema for the isAttachmentSandboxDetonationEnabled transformation."""

    class Config:
        extra = "allow"
