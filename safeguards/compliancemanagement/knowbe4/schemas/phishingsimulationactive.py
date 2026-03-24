from typing import Dict, List, Optional
from pydantic import BaseModel


class PhishingsimulationactiveInput(BaseModel):
    campaigns: Optional[List[Dict]] = None
