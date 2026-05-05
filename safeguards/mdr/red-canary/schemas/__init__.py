"""Schema registry for this vendor's transformations."""

from .isMDREnabled import IsMDREnabledInput
from .isMDRLoggingEnabled import IsMDRLoggingEnabledInput
from .requiredCoveragePercentage import RequiredCoveragePercentageInput

__all__ = [
    "IsMDREnabledInput",
    "IsMDRLoggingEnabledInput",
    "RequiredCoveragePercentageInput",
]
