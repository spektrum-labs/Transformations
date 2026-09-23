"""Schema registry for this vendor's transformations."""

from .endpointOperationalStatusUnprotectedCount import EndpointOperationalStatusUnprotectedCountInput
from
from .isAgentDeployed import IsAgentDeployedInput
from .isBitLockerRecoveryKeyEscrowed import IsBitLockerRecoveryKeyEscrowedInput
from
from .isDeviceAutoApprovalDisabled import IsDeviceAutoApprovalDisabledInput
from .isDeviceOSVersionVisible import IsDeviceOSVersionVisibleInput
from
from .isEDRDeployed import IsEDRDeployedInput
from
from .isEPPConfigured import IsEPPConfiguredInput
from .isEPPDeployed import IsEPPDeployedInput
from .isEPPMisconfigured import IsEPPMisconfiguredInput
from
from .isEncryptionEnabled import IsEncryptionEnabledInput
from .isMaintenanceModeTimeLimited import IsMaintenanceModeTimeLimitedInput
from .isPatchAutoApprovalRestricted import IsPatchAutoApprovalRestrictedInput
from .isPatchManagementEnabled import IsPatchManagementEnabledInput
from .isPatchManagementValid import IsPatchManagementValidInput
from .isSignatureUpToDate import IsSignatureUpToDateInput
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
    "IsPatchAutoApprovalRestrictedInput",
    "IsPatchManagementEnabledInput",
    "IsPatchManagementValidInput",
    "IsSignatureUpToDateInput",
    "IsThirdPartyPatchManagementEnabledInput",
    "OfflineSensorCountInput",
    "PendingApprovalRequestCountInput",
    "ScanFailureCountInput",
    "StaleSensorCountInput",
]
