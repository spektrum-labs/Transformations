"""Schema registry for this vendor's transformations."""

from .isImposterEmailDetectionEnabled import IsImposterEmailDetectionEnabledInput
from .isThreatCampaignCorrelationEnabled import IsThreatCampaignCorrelationEnabledInput
from .isVendorEmailCompromiseDetectionEnabled import IsVendorEmailCompromiseDetectionEnabledInput

__all__ = [
    "IsImposterEmailDetectionEnabledInput",
    "IsThreatCampaignCorrelationEnabledInput",
    "IsVendorEmailCompromiseDetectionEnabledInput",
]
