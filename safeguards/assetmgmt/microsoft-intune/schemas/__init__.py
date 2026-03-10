"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isdeviceinventoryactive import IsdeviceinventoryactiveInput
from .isdeviceinventorycurrent import IsdeviceinventorycurrentInput
from .isconfigurationmanaged import IsconfigurationmanagedInput
from .isdeviceconfigured import IsdeviceconfiguredInput
from .isdeviceencryptionenforced import IsdeviceencryptionenforcedInput
from .isosversioncurrent import IsosversioncurrentInput
from .ispatchmanagementenabled import IspatchmanagementenabledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsdeviceinventoryactiveInput",
    "IsdeviceinventorycurrentInput",
    "IsconfigurationmanagedInput",
    "IsdeviceconfiguredInput",
    "IsdeviceencryptionenforcedInput",
    "IsosversioncurrentInput",
    "IspatchmanagementenabledInput",
]
