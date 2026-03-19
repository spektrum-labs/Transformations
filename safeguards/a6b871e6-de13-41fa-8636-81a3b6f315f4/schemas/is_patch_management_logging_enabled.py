"""Schema for is_patch_management_logging_enabled transformation input."""

from .is_patch_management_enabled import IsPatchManagementEnabledInput


class IsPatchManagementLoggingEnabledInput(IsPatchManagementEnabledInput):
    """
    Expected input schema for the is_patch_management_logging_enabled transformation.

    This schema shares the same structure as IsPatchManagementEnabledInput since it
    processes the same Qualys Host List VM Detection API response (filtered by
    is_patchable=1). The transformation checks that HOST entries contain
    DETECTION_LIST data, confirming detections are being logged.
    """
    pass
