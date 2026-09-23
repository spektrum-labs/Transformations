"""Schema registry for this vendor's transformations."""

from .epp_transform import EppTransformInput

__all__
from .isEDREnabled import IsEDREnabledInput
from .requiredCoveragePercentage import RequiredCoveragePercentageInput

__all__ = [
    "EppTransformInput",
    "IsEDREnabledInput",
    "RequiredCoveragePercentageInput",
]
