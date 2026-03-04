"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isauditloggingenabled import IsauditloggingenabledInput
from .isdlpenabled import IsdlpenabledInput
from .isfirewallenabled import IsfirewallenabledInput
from .ismalwareprotectionenabled import IsmalwareprotectionenabledInput
from .issandboxenabled import IssandboxenabledInput
from .issslinspectionenabled import IssslinspectionenabledInput
from .isurlfilteringenabled import IsurlfilteringenabledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsauditloggingenabledInput",
    "IsdlpenabledInput",
    "IsfirewallenabledInput",
    "IsmalwareprotectionenabledInput",
    "IssandboxenabledInput",
    "IssslinspectionenabledInput",
    "IsurlfilteringenabledInput",
]
