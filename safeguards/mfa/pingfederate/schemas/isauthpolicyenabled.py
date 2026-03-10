"""Schema for isauthpolicyenabled transformation input."""
from typing import Optional, Union

from pydantic import BaseModel, Field


class IsauthpolicyenabledInput(BaseModel):
    """Expected input schema for the isauthpolicyenabled transformation. Criteria key: isAuthPolicyEnabled"""

    enableIdpAuthnSelection: Optional[Union[bool, str]] = Field(
        None, description="Whether authentication policy selection is enabled for IdP-initiated flows"
    )

    class Config:
        extra = "allow"
