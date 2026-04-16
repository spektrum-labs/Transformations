"""Schema for isaccesspolicyconfigured transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field


class SessionPolicy(BaseModel):
    id: Optional[int] = None
    display_name: Optional[str] = None
    code_name: Optional[str] = None
    description: Optional[str] = None
    screen_sharing: Optional[Union[str, bool]] = Field(None, description="Screen sharing permission")
    command_shell: Optional[Union[str, bool]] = Field(None, description="Command shell permission")
    remote_control: Optional[Union[str, bool]] = Field(None, description="Remote control permission")
    file_transfer: Optional[Union[str, bool]] = Field(None, description="File transfer permission")
    canned_scripts: Optional[Union[str, bool]] = Field(None, description="Canned scripts permission")
    session_recording: Optional[Union[str, bool]] = Field(None, description="Session recording permission")
    elevation_prompt: Optional[Union[str, bool]] = Field(None, description="Elevation prompt permission")

    class Config:
        extra = "allow"


class IsaccesspolicyconfiguredInput(BaseModel):
    """Expected input: response from GET /api/config/v1/session_policy."""
    session_policies: Optional[List[SessionPolicy]] = Field(None, description="List of session policies")

    class Config:
        extra = "allow"
