"""Schema registry for this vendor's transformations."""

from .endpointOperationalStatusUnprotectedCount import EndpointOperationalStatusUnprotectedCountInput
from .isAgentDeployed import IsAgentDeployedInput
from .isBitLockerRecoveryKeyEscrowed import IsBitLockerRecoveryKeyEscrowedInput
from .isDeviceOSVersionVisible import IsDeviceOSVersionVisibleInput
from .isDeviceOfflineAlertingEnabled import IsDeviceOfflineAlertingEnabledInput
from .isEDRDeployed import IsEDRDeployedInput
from .isEPPConfigured import IsEPPConfiguredInput
from .isEPPDeployed import IsEPPDeployedInput
from .isEPPEnabled import IsEPPEnabledInput
from .isEPPMisconfigured import IsEPPMisconfiguredInput
from .isEncryptionEnabled import IsEncryptionEnabledInput
from .isMaintenanceModeTimeLimited import IsMaintenanceModeTimeLimitedInput
from .isPatchManagementEnabled import IsPatchManagementEnabledInput
from .isPatchManagementValid import IsPatchManagementValidInput
from .isSignatureUpToDate import IsSignatureUpToDateInput
from .isThirdPartyPatchManagementEnabled import IsThirdPartyPatchManagementEnabledInput
from .offlineSensorCount import OfflineSensorCountInput
from .pendingApprovalRequestCount import PendingApprovalRequestCountInput
from .scanFailureCount import ScanFailureCountInput
from .staleSensorCount import StaleSensorCountInput

__all__ = [
    "EndpointOperationalStatusUnprotectedCountInput",
    "IsAgentDeployedInput",
    "IsBitLockerRecoveryKeyEscrowedInput",
    "IsDeviceAutoApprovalDisabledInput",
    "IsDeviceOSVersionVisibleInput",
    "IsDeviceOfflineAlertingEnabledInput",
    "IsEDRDeployedInput",
    "IsEPPConfiguredInput",
    "IsEPPDeployedInput",
    "IsEPPEnabledInput",
    "IsEPPMisconfiguredInput",
    "IsEncryptionEnabledInput",
    "IsMaintenanceModeTimeLimitedInput",
    "IsPatchManagementEnabledInput",
    "IsPatchManagementValidInput",
    "IsSignatureUpToDateInput",
    "IsThirdPartyPatchManagementEnabledInput",
    "OfflineSensorCountInput",
    "PendingApprovalRequestCountInput",
    "ScanFailureCountInput",
    "StaleSensorCountInput",
]
