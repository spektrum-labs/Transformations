"""Schema registry for this vendor's transformations."""

from .controlReadinessPercentage import ControlReadinessPercentageInput
from .deviceMonitoringInstallCompletionRate import DeviceMonitoringInstallCompletionRateInput
from .failingMonitoringTestsCount import FailingMonitoringTestsCountInput
from .openCriticalVulnerabilitiesCount import OpenCriticalVulnerabilitiesCountInput
from .openRisksCount import OpenRisksCountInput
from .overdueTestRemediationCount import OverdueTestRemediationCountInput
from .overdueVulnerabilityRemediationCount import OverdueVulnerabilityRemediationCountInput
from .staleEvidenceArtifactsCount import StaleEvidenceArtifactsCountInput
from .vendorRiskAssessmentCoveragePercentage import VendorRiskAssessmentCoveragePercentageInput

__all__ = [
    "ControlReadinessPercentageInput",
    "DeviceMonitoringInstallCompletionRateInput",
    "FailingMonitoringTestsCountInput",
    "OpenCriticalVulnerabilitiesCountInput",
    "OpenRisksCountInput",
    "OverdueTestRemediationCountInput",
    "OverdueVulnerabilityRemediationCountInput",
    "StaleEvidenceArtifactsCountInput",
    "VendorRiskAssessmentCoveragePercentageInput",
]
