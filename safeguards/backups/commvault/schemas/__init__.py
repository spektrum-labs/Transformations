"""Pydantic schemas for Commvault backup transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isairgapprotectenabled import IsairgapprotectenabledInput
from .isbackupenabled import IsbackupenabledInput
from .isbackupenabledforcriticalsystems import IsbackupenabledforcriticalsystemsInput
from .isbackupencrypted import IsbackupencryptedInput
from .isbackupimmutable import IsbackupimmutableInput
from .isbackuploggingenabled import IsbackuploggingenabledInput
from .isbackuptested import IsbackuptestedInput
from .isbackuptypesscheduled import IsbackuptypesscheduledInput
from .isransomwareprotectionenabled import IsransomwareprotectionenabledInput
from .issamlenforced import IssamlenforcedInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsairgapprotectenabledInput",
    "IsbackupenabledInput",
    "IsbackupenabledforcriticalsystemsInput",
    "IsbackupencryptedInput",
    "IsbackupimmutableInput",
    "IsbackuploggingenabledInput",
    "IsbackuptestedInput",
    "IsbackuptypesscheduledInput",
    "IsransomwareprotectionenabledInput",
    "IssamlenforcedInput",
]
