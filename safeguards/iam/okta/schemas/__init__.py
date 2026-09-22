"""Schema registry for this vendor's transformations."""

from .areAdminAccountsSeparate import AreAdminAccountsSeparateInput
from .isAdminMFAPhishingResistant import IsAdminMFAPhishingResistantInput
from .phishResistantMfaCoveragePercentage import PhishResistantMfaCoveragePercentageInput

__all__ = [
    "AreAdminAccountsSeparateInput",
    "IsAdminMFAPhishingResistantInput",
    "PhishResistantMfaCoveragePercentageInput",
]
