"""Schema registry for this vendor's transformations."""

from .confirmedLicensePurchased import ConfirmedLicensePurchasedInput
from .isEPPEnabled import IsEPPEnabledInput
from .requiredCoveragePercentage import RequiredCoveragePercentageInput

__all__ = [
    "ConfirmedLicensePurchasedInput",
    "IsEPPEnabledInput",
    "RequiredCoveragePercentageInput",
]
