from typing import Dict, List, Optional
from pydantic import BaseModel


class IstrainingenabledInput(BaseModel):
    campaigns: Optional[List[Dict]] = None
