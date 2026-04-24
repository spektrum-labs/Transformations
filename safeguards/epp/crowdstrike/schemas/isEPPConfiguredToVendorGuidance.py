"""Schema for isEPPConfiguredToVendorGuidance transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class SliderValue(BaseModel):
    """Slider-type prevention setting value with detection and prevention modes."""
    detection: Optional[str] = Field(default=None, description="Detection mode: DISABLED, MODERATE, AGGRESSIVE, EXTRA_AGGRESSIVE")
    prevention: Optional[str] = Field(default=None, description="Prevention mode: DISABLED, MODERATE, AGGRESSIVE, EXTRA_AGGRESSIVE")

    class Config:
        extra = "allow"


class PreventionSetting(BaseModel):
    """A single setting entry within a prevention settings category."""
    id: Optional[str] = Field(default=None, description="Setting identifier, e.g. cloud_anti_malware")
    name: Optional[str] = Field(default=None)
    type: Optional[str] = Field(default=None, description="Setting type: toggle, mlslider, etc.")
    value: Optional[Union[SliderValue, bool, str, Dict[str, Any]]] = Field(default=None)

    class Config:
        extra = "allow"


class PreventionSettingsCategory(BaseModel):
    """A category grouping within prevention_settings."""
    name: Optional[str] = Field(default=None)
    settings: Optional[List[PreventionSetting]] = Field(default=None)

    class Config:
        extra = "allow"


class PreventionPolicyVendorGuidance(BaseModel):
    """A single CrowdStrike prevention policy resource for vendor guidance evaluation."""
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    enabled: Optional[Union[bool, str]] = Field(default=None)
    prevention_settings: Optional[List[PreventionSettingsCategory]] = Field(default=None, description="Nested list of setting categories, each containing a settings list")
    settings: Optional[Dict[str, Any]] = Field(default=None, description="Flat dict of settings keyed by setting id (alternative shape)")
    groups: Optional[List[Any]] = Field(default=None)
    platform_name: Optional[str] = Field(default=None)

    class Config:
        extra = "allow"


class GetPreventionPoliciesResult(BaseModel):
    """Shape returned by the getPreventionPolicies method."""
    resources: Optional[List[PreventionPolicyVendorGuidance]] = Field(default=None)

    class Config:
        extra = "allow"


class IsEPPConfiguredToVendorGuidanceInput(BaseModel):
    """Expected input shape for the isEPPConfiguredToVendorGuidance transformation.

    Reads getPreventionPolicies.resources from the merged workflow output, or a flat
    top-level resources list for legacy direct-API inputs.
    """
    getPreventionPolicies: Optional[GetPreventionPoliciesResult] = Field(default=None, description="Merged getPreventionPolicies result")
    resources: Optional[List[PreventionPolicyVendorGuidance]] = Field(default=None, description="Flat resources list (legacy / direct API format)")

    class Config:
        extra = "allow"
