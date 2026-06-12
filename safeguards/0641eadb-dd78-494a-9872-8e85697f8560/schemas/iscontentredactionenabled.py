"""Schema for iscontentredactionenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscontentredactionenabledInput(BaseModel):
    """
    Expected input schema for the iscontentredactionenabled transformation.
    Criteria key: isContentRedactionEnabled
    """

    class Config:
        extra = "allow"
