"""Schema for isjitaccessenabled transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class ApplicationRecord(BaseModel):
    """Individual application object from Britive /api/apps."""
    appContainerId: Optional[str] = Field(None, description="Application container identifier")
    status: Optional[str] = Field(None, description="Application status (active/inactive)")
    hasValidPaps: Optional[Union[bool, str]] = Field(None, description="Whether the app has valid privileged access profiles")
    catalogAppDisplayName: Optional[str] = Field(None, description="Display name from the app catalog")

    class Config:
        extra = "allow"


class IsjitaccessenabledInput(BaseModel):
    """Expected input schema for the isjitaccessenabled transformation. Criteria key: isJITAccessEnabled"""
    data: Optional[List[ApplicationRecord]] = Field(None, description="List of application objects")
    apps: Optional[List[ApplicationRecord]] = Field(None, description="Alternate list of application objects")

    class Config:
        extra = "allow"
