from pydantic import BaseModel


class IsClickTimeURLRewriteEnabledInput(BaseModel):
    """Input schema for the isClickTimeURLRewriteEnabled transformation."""

    class Config:
        extra = "allow"
