"""Schema registry for this vendor's transformations."""

from .isBackupEnabled import IsBackupEnabledInput
from .isBackupEnabledForCriticalSystems import IsBackupEnabledForCriticalSystemsInput
from .isBackupTypesScheduled import IsBackupTypesScheduledInput
from .isProtectionPolicyRPOWithinSLA import IsProtectionPolicyRPOWithinSLAInput
from .isRansomwareDetectionEnabled import IsRansomwareDetectionEnabledInput
from .staleProtectionJobsCount import StaleProtectionJobsCountInput
from .unprotectedResourcesCount import UnprotectedResourcesCountInput

__all__ = [
    "IsBackupEnabledForCriticalSystemsInput",
    "IsBackupEnabledInput",
    "IsBackupTypesScheduledInput",
    "IsProtectionPolicyRPOWithinSLAInput",
    "IsRansomwareDetectionEnabledInput",
    "StaleProtectionJobsCountInput",
    "UnprotectedResourcesCountInput",
]
