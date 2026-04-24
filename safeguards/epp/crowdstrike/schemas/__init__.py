"""Schema registry for this vendor's transformations."""

from .confirmLicensePurchased import ConfirmLicensePurchasedInput
from .epp_transform import EppTransformInput

__all__
from .isEPPConfiguredToVendorGuidance import IsEPPConfiguredToVendorGuidanceInput
from .isEPPEnabledForCriticalSystems import IsEPPEnabledForCriticalSystemsInput

__all__ = [
    "ConfirmLicensePurchasedInput",
    "EppTransformInput",
    "IsEPPConfiguredToVendorGuidanceInput",
    "IsEPPEnabledForCriticalSystemsInput",
]
