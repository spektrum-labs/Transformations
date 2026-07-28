"""Schema for iscodeexecutionegresscontrolled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscodeexecutionegresscontrolledInput(BaseModel):
    """
    Expected input schema for the iscodeexecutionegresscontrolled transformation.
    Criteria key: isCodeExecutionEgressControlled
    """

    class Config:
        extra = "allow"
