"""Schema for istrainingenabled transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SimulationItem(BaseModel):
    """A single training simulation from the NINJIO API."""
    status: Optional[str] = Field(None, description="Simulation status (e.g. active, scheduled, running)")
    state: Optional[str] = Field(None, description="Alternate status field")
    simulationStatus: Optional[str] = Field(None, description="Alternate simulation status field")

    class Config:
        extra = "allow"


class IstrainingenabledInput(BaseModel):
    """Expected input schema for the istrainingenabled transformation. Criteria key: isTrainingEnabled"""
    results: Optional[List[SimulationItem]] = Field(None, description="List of training simulations")
    data: Optional[Any] = Field(None, description="Alternate key for simulations list or nested data")
    simulations: Optional[List[SimulationItem]] = Field(None, description="Alternate key for simulations list")
    items: Optional[List[SimulationItem]] = Field(None, description="Alternate key for simulations list")

    class Config:
        extra = "allow"
