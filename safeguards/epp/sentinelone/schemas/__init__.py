"""Schema registry for this vendor's transformations."""

from .confirmedLicensePurchased import ConfirmedLicensePurchasedInput
from .isEPPConfigured import IsEPPConfiguredInput
from .isEPPEnabled import IsEPPEnabledInput

__all__ = [
    "ConfirmedLicensePurchasedInput",
    "IsEPPConfiguredInput",
    "IsEPPEnabledInput",
]
