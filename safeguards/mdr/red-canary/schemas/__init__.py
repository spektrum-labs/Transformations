"""Schema registry for this vendor's transformations."""

from .isMDREnabled import IsMDREnabledInput
from .isMDRLoggingEnabled import IsMDRLoggingEnabledInput
from .requiredCoveragePercentage import RequiredCoveragePercentageInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .iscloudmonitoringenabled import IscloudmonitoringenabledInput
from .isalertingconfigured import IsalertingconfiguredInput
from .isendpointcoveragevalid import IsendpointcoveragevalidInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IscloudmonitoringenabledInput",
    "IsalertingconfiguredInput",
    "IsendpointcoveragevalidInput",
    "IsMDREnabledInput",
    "IsMDRLoggingEnabledInput",
    "RequiredCoveragePercentageInput",
]
