"""Schema for iscloudassetinventorytracked transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class NetskopeApplicationEvent(BaseModel):
    """Single application event from /api/v2/events/data/application - represents
    a user's interaction with a cloud application, which is the underlying data
    source for Netskope's CASB cloud asset (Shadow IT) inventory."""

    app: Optional[str] = Field(
        default=None,
        description="Cloud application name (e.g., 'Slack', 'Salesforce')"
    )
    application: Optional[str] = Field(
        default=None,
        description="Alternate application name field"
    )
    appname: Optional[str] = Field(
        default=None,
        description="Alternate application name field"
    )
    appcategory: Optional[str] = Field(
        default=None,
        description="Application category (e.g., 'Collaboration', 'Storage', 'CRM')"
    )
    category: Optional[str] = Field(
        default=None,
        description="Alternate category field"
    )
    ccl: Optional[str] = Field(
        default=None,
        description="Cloud Confidence Level (low, medium, high, etc.)"
    )
    activity: Optional[str] = Field(
        default=None,
        description="User activity (upload, download, share, etc.)"
    )
    action: Optional[str] = Field(
        default=None,
        description="Alternate activity field"
    )
    user: Optional[str] = Field(
        default=None,
        description="User who triggered the event"
    )
    user_name: Optional[str] = Field(
        default=None,
        description="Alternate user identifier"
    )
    src_user: Optional[str] = Field(
        default=None,
        description="Alternate source user identifier"
    )
    sanctioned_instance: Optional[Union[str, bool]] = Field(
        default=None,
        description="Whether the application instance is sanctioned (yes/no/true/false)"
    )
    classification: Optional[str] = Field(
        default=None,
        description="Application classification (sanctioned, unsanctioned, shadow IT)"
    )
    app_tags: Optional[str] = Field(
        default=None,
        description="Tags applied to the application"
    )
    instance_id: Optional[str] = Field(
        default=None,
        description="Application instance identifier"
    )
    policy: Optional[str] = Field(
        default=None,
        description="Matched Netskope policy, if any"
    )
    timestamp: Optional[int] = Field(
        default=None,
        description="Epoch timestamp of the event"
    )

    class Config:
        extra = "allow"


class IscloudassetinventorytrackedInput(BaseModel):
    """
    Expected input schema for the iscloudassetinventorytracked transformation.
    Criteria key: isCloudAssetInventoryTracked

    Validates cloud asset inventory via /api/v2/events/data/application.
    Application events represent users' interactions with cloud apps - the
    data source for Netskope's CASB / Shadow IT discovery.
    """

    ok: Optional[Union[int, bool]] = Field(
        default=None,
        description="Netskope response status flag (1 = success)"
    )
    status: Optional[str] = Field(
        default=None,
        description="Top-level status field"
    )
    result: Optional[List[NetskopeApplicationEvent]] = Field(
        default=None,
        description="Array of application events returned by Netskope REST API v2"
    )
    data: Optional[List[NetskopeApplicationEvent]] = Field(
        default=None,
        description="Alternate events array"
    )
    events: Optional[List[NetskopeApplicationEvent]] = Field(
        default=None,
        description="Alternate events array"
    )
    items: Optional[List[NetskopeApplicationEvent]] = Field(
        default=None,
        description="Alternate events array"
    )
    value: Optional[List[NetskopeApplicationEvent]] = Field(
        default=None,
        description="Alternate events array"
    )
    total: Optional[int] = Field(
        default=None,
        description="Total events returned by the response"
    )

    class Config:
        extra = "allow"
