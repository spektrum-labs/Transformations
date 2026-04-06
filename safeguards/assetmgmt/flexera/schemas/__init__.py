"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isassetinventorycomplete import IsassetinventorycompleteInput
from .isintegrationhealthy import IsintegrationhealthyInput
from .islifecyclemanaged import IslifecyclemanagedInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsassetinventorycompleteInput",
    "IsintegrationhealthyInput",
    "IslifecyclemanagedInput",
]
