from typing import Dict, List, Optional
from pydantic import BaseModel


class TrainingcompletionrateInput(BaseModel):
    enrollments: Optional[List[Dict]] = None
