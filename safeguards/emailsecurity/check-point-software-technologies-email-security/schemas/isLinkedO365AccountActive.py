from pydantic import BaseModel
from typing import Optional


class IsLinkedO365AccountActiveInput(BaseModel):
    """Input schema for the isLinkedO365AccountActive transformation.

    Wraps the getEntityById (search/entity) response, which may include:
      - responseEnvelope: dict with totalRecordsNumber, scrollId, etc.
      - responseData: dict or list of entity objects, each with saas,
        saasEntityType, entityId, entityCreated, entityPayload.
      - error-shaped fields (error, errorType, statusCode, message) when
        authentication or API errors occur.
    """

    class Config:
        extra = "allow"
