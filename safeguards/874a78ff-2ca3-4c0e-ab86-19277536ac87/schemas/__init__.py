"""Pydantic schemas for transformation inputs."""

from .areadminaccountsseparate import AreadminaccountsseparateInput
from .areantiphishingpoliciesconfigured import AreantiphishingpoliciesconfiguredInput
from .aredlppoliciesconfigured import AredlppoliciesconfiguredInput
from .aretransportrulesconfigured import AretransportrulesconfiguredInput
from .authtypesallowed import AuthtypesallowedInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isadminmfaphishingresistant import IsadminmfaphishingresistantInput
from .isantiphishingenabled import IsantiphishingenabledInput
from .isappconsentrestricted import IsappconsentrestrictedInput
from .isattachmentscanningenabled import IsattachmentscanningenabledInput
from .isautoforwarddisabled import IsautoforwarddisabledInput
from .isbannermodeenforced import IsbannermodeenforcedInput
from .isdataclassificationenabled import IsdataclassificationenabledInput
from .isdkimconfigured import IsdkimconfiguredInput
from .isdmarcconfigured import IsdmarcconfiguredInput
from .isdnsconfigured import IsdnsconfiguredInput
from .isemailfilteringenabled import IsemailfilteringenabledInput
from .isemailsecurityloggingenabled import IsemailsecurityloggingenabledInput
from .isinformationrightsmanagementenabled import IsinformationrightsmanagementenabledInput
from .islegacyauthblocked import IslegacyauthblockedInput
from .ismacroblockingenabled import IsmacroblockingtenabledInput
from .ismailboxauditingenabled import IsmailboxauditingenabledInput
from .ismfaenforcedforusers import IsmfaenforcedforusersInput
from .issafeattachmentsenabled import IssafeattachmentsenabledInput
from .issafelinksenabled import IssafelinksenabledInput
from .issafelinksprotectionenabled import IssafelinksprotectionenabledInput
from .issmtpauthdisabled import IssmtpauthdisabledInput
from .isspfconfigured import IsspfconfiguredInput
from .isssoenabled import IsssoenabledInput
from .istransportrulebannerenabled import IstransportrulebannerenabledInput
from .istransportrulebannerenforced import IstransportrulebannerenforcedInput
from .isurlrewriteenabled import IsurlrewriteenabledInput

__all__ = [
    "AreadminaccountsseparateInput",
    "AreantiphishingpoliciesconfiguredInput",
    "AredlppoliciesconfiguredInput",
    "AretransportrulesconfiguredInput",
    "AuthtypesallowedInput",
    "ConfirmedlicensepurchasedInput",
    "IsadminmfaphishingresistantInput",
    "IsantiphishingenabledInput",
    "IsappconsentrestrictedInput",
    "IsattachmentscanningenabledInput",
    "IsautoforwarddisabledInput",
    "IsbannermodeenforcedInput",
    "IsdataclassificationenabledInput",
    "IsdkimconfiguredInput",
    "IsdmarcconfiguredInput",
    "IsdnsconfiguredInput",
    "IsemailfilteringenabledInput",
    "IsemailsecurityloggingenabledInput",
    "IsinformationrightsmanagementenabledInput",
    "IslegacyauthblockedInput",
    "IsmacroblockingtenabledInput",
    "IsmailboxauditingenabledInput",
    "IsmfaenforcedforusersInput",
    "IssafeattachmentsenabledInput",
    "IssafelinksenabledInput",
    "IssafelinksprotectionenabledInput",
    "IssmtpauthdisabledInput",
    "IsspfconfiguredInput",
    "IsssoenabledInput",
    "IstransportrulebannerenabledInput",
    "IstransportrulebannerenforcedInput",
    "IsurlrewriteenabledInput",
]
