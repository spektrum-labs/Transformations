"""Schema for hasactiveemployees transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EmployeeItem(BaseModel):
    """A single employee record from the NINJIO API."""
    status: Optional[str] = Field(None, description="Employee status (e.g. active, inactive, deleted)")
    state: Optional[str] = Field(None, description="Alternate status field")
    employeeStatus: Optional[str] = Field(None, description="Alternate employee status field")

    class Config:
        extra = "allow"


class HasactiveemployeesInput(BaseModel):
    """Expected input schema for the hasactiveemployees transformation. Criteria key: hasActiveEmployees"""
    total: Optional[int] = Field(None, description="Total employee count (pagination-aware)")
    count: Optional[int] = Field(None, description="Alternate total count field")
    totalCount: Optional[int] = Field(None, description="Alternate total count field (camelCase)")
    total_count: Optional[int] = Field(None, description="Alternate total count field (snake_case)")
    employees: Optional[List[EmployeeItem]] = Field(None, description="List of employee records")
    results: Optional[List[EmployeeItem]] = Field(None, description="Alternate key for employees list")
    data: Optional[Any] = Field(None, description="Alternate key for employees list or nested data")
    items: Optional[List[EmployeeItem]] = Field(None, description="Alternate key for employees list")

    class Config:
        extra = "allow"
