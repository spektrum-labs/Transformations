"""Pydantic schemas for transformation inputs."""

from .asm_transform import AsmTransformInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .is_patch_management_enabled import IsPatchManagementEnabledInput
from .is_patch_management_logging_enabled import IsPatchManagementLoggingEnabledInput

__all__ = [
    "AsmTransformInput",
    "ConfirmedlicensepurchasedInput",
    "IsPatchManagementEnabledInput",
    "IsPatchManagementLoggingEnabledInput",
]
