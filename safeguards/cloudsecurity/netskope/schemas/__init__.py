"""Pydantic schemas for Netskope transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .iscloudassetinventorytracked import IscloudassetinventorytrackedInput
from .iscloudposturemanagementenabled import IscloudposturemanagementenabledInput
from .ismisconfigurationdetectionenabled import IsmisconfigurationdetectionenabledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IscloudassetinventorytrackedInput",
    "IscloudposturemanagementenabledInput",
    "IsmisconfigurationdetectionenabledInput",
]
