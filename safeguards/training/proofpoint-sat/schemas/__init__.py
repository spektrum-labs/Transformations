"""Pydantic schemas for transformation inputs."""

from .istrainingenabled import IstrainingenabledInput
from .isphishingsimulationenabled import IsphishingsimulationenabledInput
from .iscompletionrateacceptable import IscompletionrateacceptableInput
from .isreportingenabled import IsreportingenabledInput

__all__ = [
    "IstrainingenabledInput",
    "IsphishingsimulationenabledInput",
    "IscompletionrateacceptableInput",
    "IsreportingenabledInput",
]
