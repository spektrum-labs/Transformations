"""Schema registry for this vendor's transformations."""

from .confirmedLicensePurchased import ConfirmedLicensePurchasedInput
from .isEPPConfigured import IsEPPConfiguredInput
from .isEPPEnabled import IsEPPEnabledInput
from .isEPPLoggingEnabled import IsEPPLoggingEnabledInput
from .isSSOEnabled import IsSSOEnabledInput
from .requiredCoveragePercentage import RequiredCoveragePercentageInput

__all__ = [
    "ConfirmedLicensePurchasedInput",
    "IsEPPConfiguredInput",
    "IsEPPEnabledInput",
    "IsEPPLoggingEnabledInput",
    "IsSSOEnabledInput",
    "RequiredCoveragePercentageInput",
]
