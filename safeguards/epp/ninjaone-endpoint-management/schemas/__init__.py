"""Schema registry for this vendor's transformations."""

from .confirmedLicensePurchased import ConfirmedLicensePurchasedInput
from .endpointOperationalStatusUnprotectedCount import EndpointOperationalStatusUnprotectedCountInput
from .isBitLockerRecoveryKeyEscrowed import IsBitLockerRecoveryKeyEscrowedInput
from
from .isDeviceOSVersionVisible import IsDeviceOSVersionVisibleInput
from .isEDRDeployed import IsEDRDeployedInput
from .isEPPDeployed import IsEPPDeployedInput
from .isEPPEnabled import IsEPPEnabledInput
from .isEPPMisconfigured import IsEPPMisconfiguredInput
from
from .isMaintenanceModeTimeLimited import IsMaintenanceModeTimeLimitedInput
from
from .isPatchManagementEnabled import IsPatchManagementEnabledInput
from .isPatchManagementValid import IsPatchManagementValidInput
from .isSignatureUpToDate import IsSignatureUpToDateInput
from .maintenanceModeActiveEndpointCount import MaintenanceModeActiveEndpointCountInput
from .offlineSensorCount import OfflineSensorCountInput
from .pendingApprovalRequestCount import PendingApprovalRequestCountInput
from .policyOverrideDriftCount import PolicyOverrideDriftCountInput
from .quarantinedFileCount import QuarantinedFileCountInput
from .requiredCoveragePercentage import RequiredCoveragePercentageInput
from .scanFailureCount import ScanFailureCountInput
from
from .staleSensorCount import StaleSensorCountInput

__all__ = [
    "ConfirmedLicensePurchasedInput",
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
    "MaintenanceModeActiveEndpointCountInput",
    "OfflineSensorCountInput",
    "PendingApprovalRequestCountInput",
    "PolicyOverrideDriftCountInput",
    "QuarantinedFileCountInput",
    "RequiredCoveragePercentageInput",
    "ScanFailureCountInput",
    "StaleSensorCountInput",
]
