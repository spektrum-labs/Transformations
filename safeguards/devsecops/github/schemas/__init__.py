"""Schema registry for this vendor's transformations."""

from .isAdvancedSecurityEnabled import IsAdvancedSecurityEnabledInput
from .isDependabotAlertsEnabled import IsDependabotAlertsEnabledInput
from .isSecretScanningPushProtectionEnabled import IsSecretScanningPushProtectionEnabledInput
from .openCriticalDependabotAlertsCount import OpenCriticalDependabotAlertsCountInput

__all__ = [
    "IsAdvancedSecurityEnabledInput",
    "IsDependabotAlertsEnabledInput",
    "IsSecretScanningPushProtectionEnabledInput",
    "OpenCriticalDependabotAlertsCountInput",
    "OpenSecretScanningAlertsCountInput",
]
