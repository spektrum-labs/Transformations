"""Schema registry for this vendor's transformations."""

from .isAnalystVettedAlertPipelineEnabled import IsAnalystVettedAlertPipelineEnabledInput
from .isCWEClassificationEnabled import IsCWEClassificationEnabledInput
from .isNVDIndependentCoverageEnabled import IsNVDIndependentCoverageEnabledInput
from .isVulnerabilityIntelligenceEnabled import IsVulnerabilityIntelligenceEnabledInput
from .openCriticalSeverityAlertsCount import OpenCriticalSeverityAlertsCountInput
from .remediationGuidanceProvidedPercentage import RemediationGuidanceProvidedPercentageInput

__all__ = [
    "IsAnalystVettedAlertPipelineEnabledInput",
    "IsCWEClassificationEnabledInput",
    "IsNVDIndependentCoverageEnabledInput",
    "IsVulnerabilityIntelligenceEnabledInput",
    "OpenCriticalSeverityAlertsCountInput",
    "RemediationGuidanceProvidedPercentageInput",
]
