from typing import Dict, List, Optional
from pydantic import BaseModel


class AnnualtrainingcompletionrateInput(BaseModel):
    enrollments: Optional[List[Dict]] = None
