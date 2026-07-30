"""Schema registry for this vendor's transformations."""

from .isBehavioralMonitoringValid import IsBehavioralMonitoringValidInput
from .isEDRDeployed import IsEDRDeployedInput
from .isEPPConfigured import IsEPPConfiguredInput
from .isEPPDeployed import IsEPPDeployedInput
from .isEPPEnabled import IsEPPEnabledInput
from .isEPPEnabledForCriticalSystems import IsEPPEnabledForCriticalSystemsInput
from .isEPPLoggingEnabled import IsEPPLoggingEnabledInput
from .isPatchManagementEnabled import IsPatchManagementEnabledInput
from .isPatchManagementValid import IsPatchManagementValidInput
from .isRemovableMediaControlled import IsRemovableMediaControlledInput
from .requiredCoveragePercentage import RequiredCoveragePercentageInput

__all__ = [
    "IsBehavioralMonitoringValidInput",
    "IsEDRDeployedInput",
    "IsEPPConfiguredInput",
    "IsEPPDeployedInput",
    "IsEPPEnabledForCriticalSystemsInput",
    "IsEPPEnabledInput",
    "IsEPPLoggingEnabledInput",
    "IsPatchManagementEnabledInput",
    "IsPatchManagementValidInput",
    "IsRemovableMediaControlledInput",
    "RequiredCoveragePercentageInput",
]
