"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isdefaultdenyconfigured import IsdefaultdenyconfiguredInput
from .isfallbackmodedisabled import IsfallbackmodedisabledInput
from .isfirewallenabled import IsfirewallenabledInput
from .isfirmwarecurrent import IsfirmwarecurrentInput
from .requiredcoveragepercentage import RequiredcoveragepercentageInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsdefaultdenyconfiguredInput",
    "IsfallbackmodedisabledInput",
    "IsfirewallenabledInput",
    "IsfirmwarecurrentInput",
    "RequiredcoveragepercentageInput",
]
