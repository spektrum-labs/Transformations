"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .istrainingenabled import IstrainingenabledInput
from .istrainingcompletiontracked import IstrainingcompletiontrackedInput
from .isphishingsimulationenabled import IsphishingsimulationenabledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IstrainingenabledInput",
    "IstrainingcompletiontrackedInput",
    "IsphishingsimulationenabledInput",
]
