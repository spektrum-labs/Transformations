# ispublicstoragebucketexposed.py - Rapid7 InsightCloudSec (Cloud Security, ff4fd43e)
#
# Method: listStorageContainers. POST {serverUrl}/v3/public/resource/query
#         {"selected_resource_type": "storagecontainer", "limit": 1000}, cursor-paged by IS
#         (request body "cursor" <- response "next_cursor"; pages merged into "resources").
# Docs:   InsightCloudSec API v3, Query Resources (docs.rapid7.com/insightcloudsec/api/v3/, spec
#         /_api/insightcloudsec-v3-api.yaml): response counts{type: n}, resources[{resource_type, <type>: {...}}],
#         next_cursor. Storage Resources (docs.rapid7.com/insightcloudsec/storage-resources/): storage container
#         field `public` - "Denotes whether the storage container is accessible by the public".
# INVERTED key: True means a storage container IS public (the insecure answer).

import json
from datetime import datetime, timedelta


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        value = json.loads(text)
    return value


def envelope_error(value):
    """An Integration-Service or vendor error envelope, as text; None when the value is not one."""
    if not isinstance(value, dict):
        return None
    err = value.get("error")
    if err:
        return "API error: " + str(err)[:200]
    if str(value.get("status", "")).lower() == "error":
        return "API error: " + str(value.get("message") or value.get("detail") or "status Error")[:200]
    code = value.get("status_code", value.get("statusCode"))
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "API error: HTTP " + str(code)
    return None


def body_of(input, marker):
    """The vendor body: input["data"] (new TS format), then IS/TS envelopes, until marker(body) is true.
    Returns (body, None) or (None, reason)."""
    value = parse(input)
    if isinstance(input, dict) and "validation" in input and "data" in input:
        value = parse(input.get("data"))
    for depth in range(5):
        problem = envelope_error(value)
        if problem:
            return None, problem
        if marker(value):
            return value, None
        if not isinstance(value, dict):
            return None, "No InsightCloudSec response body"
        nxt = None
        for wrapper in ["apiResponse", "_response_data", "response", "result"]:
            if wrapper in value:
                nxt = parse(value.get(wrapper))
                break
        if nxt is None:
            return None, "Response is not the expected InsightCloudSec body"
        value = nxt
    return None, "Response is not the expected InsightCloudSec body"


def as_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def response(key, value, extra=None, errors=None, passes=None, fails=None):
    """errors -> dataCollection.status "error": Token-Service records the criterion Unevaluated."""
    out = {key: value}
    if extra:
        out.update(extra)
    return {
        "transformedResponse": out,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": extra or {}},
            "evaluation": {"passReasons": passes or [], "failReasons": fails or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Rapid7", "product": "InsightCloudSec",
                         "category": "Cloud Security", "schemaVersion": "1.0",
                         "evaluatedAt": datetime.utcnow().isoformat() + "Z"},
        },
    }


def storage_body(value):
    return isinstance(value, dict) and isinstance(value.get("resources"), list) and isinstance(value.get("counts"), dict)


def storage_records(input, field):
    """Every storagecontainer record from the paged v3 resource query, each carrying <field>.
    Returns (records, None) or (None, reason). Fails when the pages read are fewer than the server's own count."""
    body, problem = body_of(input, storage_body)
    if problem:
        return None, problem
    total = as_count(body["counts"].get("storagecontainer"))
    if total is None:
        return None, "Response has no counts.storagecontainer, so completeness cannot be shown"
    records = []
    for item in body["resources"]:
        rec = item.get("storagecontainer") if isinstance(item, dict) else None
        if not isinstance(rec, dict):
            return None, "A resource in the response is not a storagecontainer record"
        if field not in rec:
            return None, "A storagecontainer record has no '" + field + "' field"
        records.append(rec)
    if len(records) != total:
        return None, "Read " + str(len(records)) + " of " + str(total) + " storage containers (paging incomplete)"
    return records, None


def transform(input):
    """True when any storage container reports public == true; False when all report public == false.
    None (Unevaluated) on no data, an error, a record without `public`, or fewer records than counts.storagecontainer."""
    key = "isPublicStorageBucketExposed"
    try:
        records, problem = storage_records(input, "public")
        if problem:
            return response(key, None, errors=[problem])
        public = 0
        for rec in records:
            flag = rec.get("public")
            if not isinstance(flag, bool):
                return response(key, None, errors=["A storagecontainer 'public' value is not true/false"])
            if flag:
                public = public + 1
        extra = {"publicStorageContainerCount": public, "storageContainerCount": len(records)}
        if public:
            return response(key, True, extra, fails=[str(public) + " of " + str(len(records)) + " storage containers are public"])
        return response(key, False, extra, passes=["None of " + str(len(records)) + " storage containers is public"])
    except Exception as e:
        return response(key, None, errors=["Transformation error: " + str(e)[:200]])
