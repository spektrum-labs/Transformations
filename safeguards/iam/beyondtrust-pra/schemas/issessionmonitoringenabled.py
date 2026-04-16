"""Schema for issessionmonitoringenabled transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field


class SessionPolicyRecording(BaseModel):
    id: Optional[int] = None
    display_name: Optional[str] = None
    code_name: Optional[str] = None
    session_recording: Optional[Union[str, bool]] = Field(None, description="Session recording permission (allowed/not_allowed/notdefined)")

    class Config:
        extra = "allow"


class IssessionmonitoringenabledInput(BaseModel):
    """Expected input: response from GET /api/config/v1/session_policy."""
    session_policies: Optional[List[SessionPolicyRecording]] = Field(None, description="List of session policies")

    class Config:
        extra = "allow"
