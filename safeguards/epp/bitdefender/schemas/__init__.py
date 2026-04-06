"""Pydantic schemas for transformation inputs."""

from .confirmedLicensePurchased import ConfirmedlicensepurchasedInput
from .isBehavioralMonitoringValid import IsbehavioralmonitoringvalidInput
from .isEDRDeployed import IsedrdeployedInput
from .isEPPDeployed import IseppdeployedInput
from .isEPPMisconfigured import IseppmisconfiguredInput
from .isPatchManagementEnabled import IspatchmanagementenabledInput
from .isRemovableMediaControlled import IsremovablemediacontrolledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsbehavioralmonitoringvalidInput",
    "IsedrdeployedInput",
    "IseppdeployedInput",
    "IseppmisconfiguredInput",
    "IspatchmanagementenabledInput",
    "IsremovablemediacontrolledInput",
]
