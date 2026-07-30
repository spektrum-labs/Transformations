"""Schema for the NinjaOne epp_transform input.

Consumes the NinjaOne /api/v2/queries/antivirus-status report, which returns
{ cursor, results: [ { productName, productState, definitionStatus, version,
deviceId, timestamp } ] }. The presence of devices reporting an active AV/EDR
product indicates endpoint protection is deployed.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EppTransformInput(BaseModel):
    """Expected input schema for the NinjaOne epp_transform transformation.

    Criteria keys: isEPPDeployed, isEDRDeployed, isEPPConfigured
    """

    results: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None
    cursor: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
