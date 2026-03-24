"""Pydantic schemas for Qualys ASM transformation inputs."""
from .externalassetinventorycount import ExternalassetinventorycountInput
from .vulnerabilityscanfrequency import VulnerabilityscanfrequencyInput
from .criticalvulnerabilitycount import CriticalvulnerabilitycountInput
from .patchcompliancepercentage import PatchcompliancepercentageInput
from .meantimetoremediatecritical import MeantimetoremediatecriticalInput
from .endoflifesoftwaredetected import EndoflifesoftwaredetectedInput
from .hashardwareassetinventory import HashardwareassetinventoryInput
from .knownexploitedvulncount import KnownexploitedvulncountInput

__all__ = [
    "ExternalassetinventorycountInput",
    "VulnerabilityscanfrequencyInput",
    "CriticalvulnerabilitycountInput",
    "PatchcompliancepercentageInput",
    "MeantimetoremediatecriticalInput",
    "EndoflifesoftwaredetectedInput",
    "HashardwareassetinventoryInput",
    "KnownexploitedvulncountInput",
]
