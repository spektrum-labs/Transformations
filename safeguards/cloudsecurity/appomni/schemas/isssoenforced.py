"""Schema for isssoenforced transformation input."""

from typing import Optional, Union

from pydantic import BaseModel, Field


class IsssoenforcedInput(BaseModel):
    """
    Expected input schema for the isssoenforced transformation.

    Criteria key: isSSOEnforced

    Evaluates that SSO/SAML is enabled AND enforced (local login disabled)
    for AppOmni access.
    """

    sso_enabled: Optional[Union[bool, str]] = Field(
        None,
        description="Whether SSO is enabled. Accepts bool or string.",
    )
    sso_enforced: Optional[Union[bool, str]] = Field(
        None,
        description="Whether SSO is enforced (primary key).",
    )
    enforce_sso: Optional[Union[bool, str]] = Field(
        None,
        description="Whether SSO is enforced (alternate key).",
    )
    local_login_allowed: Optional[Union[bool, str]] = Field(
        None,
        description="Whether local login is allowed. Defaults to True (unsafe) when absent.",
    )
    sso_provider: Optional[str] = Field(
        None,
        description="SSO provider name (primary key).",
    )
    provider: Optional[str] = Field(
        None,
        description="SSO provider name (alternate key).",
    )

    class Config:
        extra = "allow"
