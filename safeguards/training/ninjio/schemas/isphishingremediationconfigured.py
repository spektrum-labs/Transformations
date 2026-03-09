"""Schema for isphishingremediationconfigured transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RemediationSimulationItem(BaseModel):
    """A single simulation with potential remediation/teachable moment configuration."""
    type: Optional[str] = Field(None, description="Simulation type (e.g. remedial, corrective)")
    simulationType: Optional[str] = Field(None, description="Alternate simulation type field (camelCase)")
    template_type: Optional[str] = Field(None, description="Alternate simulation type field (snake_case)")
    name: Optional[str] = Field(None, description="Simulation name")
    title: Optional[str] = Field(None, description="Alternate simulation name field")
    simulationName: Optional[str] = Field(None, description="Alternate simulation name field (camelCase)")
    training_simulation_id: Optional[str] = Field(None, description="Linked training simulation ID")
    trainingSimulationId: Optional[str] = Field(None, description="Alternate linked training simulation ID (camelCase)")
    teachable_moments_id: Optional[str] = Field(None, description="Linked teachable moments ID")
    teachableMomentsId: Optional[str] = Field(None, description="Alternate teachable moments ID (camelCase)")
    remedial_training_id: Optional[str] = Field(None, description="Linked remedial training ID")
    remedialTrainingId: Optional[str] = Field(None, description="Alternate remedial training ID (camelCase)")

    class Config:
        extra = "allow"


class IsphishingremediationconfiguredInput(BaseModel):
    """Expected input schema for the isphishingremediationconfigured transformation. Criteria key: isPhishingRemediationConfigured"""
    results: Optional[List[RemediationSimulationItem]] = Field(None, description="List of simulations")
    data: Optional[Any] = Field(None, description="Alternate key for simulations list or nested data")
    simulations: Optional[List[RemediationSimulationItem]] = Field(None, description="Alternate key for simulations list")
    items: Optional[List[RemediationSimulationItem]] = Field(None, description="Alternate key for simulations list")

    class Config:
        extra = "allow"
