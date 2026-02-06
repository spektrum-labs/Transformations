"""Pydantic schemas for transformation inputs."""

from .backup_transform import BackupTransformInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isbackupenabled import IsbackupenabledInput
from .isbackupenabledforcriticalsystems import IsbackupenabledforcriticalsystemsInput
from .isbackupencrypted import IsbackupencryptedInput
from .isbackupimmutable import IsbackupimmutableInput
from .isbackuploggingenabled import IsbackuploggingenabledInput
from .isbackuptested import IsbackuptestedInput
from .isbackuptypesscheduled import IsbackuptypesscheduledInput
from .issamlenforced import IssamlenforcedInput

__all__ = [
    "BackupTransformInput",
    "ConfirmedlicensepurchasedInput",
    "IsbackupenabledInput",
    "IsbackupenabledforcriticalsystemsInput",
    "IsbackupencryptedInput",
    "IsbackupimmutableInput",
    "IsbackuploggingenabledInput",
    "IsbackuptestedInput",
    "IsbackuptypesscheduledInput",
    "IssamlenforcedInput",
]
