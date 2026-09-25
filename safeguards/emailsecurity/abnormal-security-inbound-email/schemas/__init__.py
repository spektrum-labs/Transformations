"""Schema registry for this vendor's transformations."""

from .isAntiPhishingEnabled import IsAntiPhishingEnabledInput
from .isImposterEmailDetectionEnabled import IsImposterEmailDetectionEnabledInput
from .isThreatCampaignCorrelationEnabled import IsThreatCampaignCorrelationEnabledInput
from .isVendorEmailCompromiseDetectionEnabled import IsVendorEmailCompromiseDetectionEnabledInput

__all__ = [
    "IsAntiPhishingEnabledInput",
    "IsImposterEmailDetectionEnabledInput",
    "IsThreatCampaignCorrelationEnabledInput",
    "IsVendorEmailCompromiseDetectionEnabledInput",
]
