"""Schema registry for this vendor's transformations."""

from .isAccountTakeoverDetectionEnabled import IsAccountTakeoverDetectionEnabledInput
from .isImposterEmailDetectionEnabled import IsImposterEmailDetectionEnabledInput
from .isThreatCampaignCorrelationEnabled import IsThreatCampaignCorrelationEnabledInput
from .isVendorEmailCompromiseDetectionEnabled import IsVendorEmailCompromiseDetectionEnabledInput

__all__ = [
    "IsAccountTakeoverDetectionEnabledInput",
    "IsImposterEmailDetectionEnabledInput",
    "IsThreatCampaignCorrelationEnabledInput",
    "IsVendorEmailCompromiseDetectionEnabledInput",
]
