"""Schema registry for this vendor's transformations."""

from .confirmedLicensePurchased import ConfirmedLicensePurchasedInput
from .isAntiPhishingEnabled import IsAntiPhishingEnabledInput
from .isEmailLoggingEnabled import IsEmailLoggingEnabledInput
from .isImposterEmailDetectionEnabled import IsImposterEmailDetectionEnabledInput
from .isThreatCampaignCorrelationEnabled import IsThreatCampaignCorrelationEnabledInput
from .isVendorEmailCompromiseDetectionEnabled import IsVendorEmailCompromiseDetectionEnabledInput

__all__ = [
    "ConfirmedLicensePurchasedInput",
    "IsEmailLoggingEnabledInput",
    "IsAntiPhishingEnabledInput",
    "IsImposterEmailDetectionEnabledInput",
    "IsThreatCampaignCorrelationEnabledInput",
    "IsVendorEmailCompromiseDetectionEnabledInput",
]
