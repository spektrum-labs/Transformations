"""Schema registry for this vendor's transformations."""

from .activeEventSourceCount import ActiveEventSourceCountInput
from .hasMultiSourceTelemetryIntegration import HasMultiSourceTelemetryIntegrationInput
from .hasThreatIntelligenceFeedIntegration import HasThreatIntelligenceFeedIntegrationInput
from .incidentAnalystAssignmentPercentage import IncidentAnalystAssignmentPercentageInput
from .maliciousVerdictOpenIncidentsCount import MaliciousVerdictOpenIncidentsCountInput
from .meanTimeToVerificationAckMinutesCount import MeanTimeToVerificationAckMinutesCountInput
from .oldestOpenCriticalInvestigationAgeDaysCount import OldestOpenCriticalInvestigationAgeDaysCountInput
from .openCriticalSeverityIncidentsCount import OpenCriticalSeverityIncidentsCountInput
from .unassignedOpenInvestigationsCount import UnassignedOpenInvestigationsCountInput

__all__ = [
    "ActiveEventSourceCountInput",
    "HasMultiSourceTelemetryIntegrationInput",
    "HasThreatIntelligenceFeedIntegrationInput",
    "IncidentAnalystAssignmentPercentageInput",
    "MaliciousVerdictOpenIncidentsCountInput",
    "MeanTimeToVerificationAckMinutesCountInput",
    "OldestOpenCriticalInvestigationAgeDaysCountInput",
    "OpenCriticalSeverityIncidentsCountInput",
    "UnassignedOpenInvestigationsCountInput",
]
