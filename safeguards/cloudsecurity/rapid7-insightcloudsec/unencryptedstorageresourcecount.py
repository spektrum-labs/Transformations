# unencryptedstorageresourcecount.py - Rapid7 InsightCloudSec (Cloud Security, ff4fd43e)
#
# Method: listStorageContainers (see ispublicstoragebucketexposed.py): every storagecontainer record, cursor-paged.
# Docs:   Storage Resources (docs.rapid7.com/insightcloudsec/storage-resources/): `global_encryption` - "Default
#         server side encryption for storage container". A record whose global_encryption is null, false, empty,
#         "none" or "disabled" is counted as unencrypted. policy_encryption (object level) is not counted.

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

OFF = ["", "none", "null", "false", "disabled", "off"]


def transform(input):
    """Count of storage containers with no default server-side encryption.
    None (Unevaluated) on no data, an error, a record without `global_encryption`, or incomplete paging."""
    key = "unencryptedStorageResourceCount"
    try:
        records, problem = storage_records(input, "global_encryption")
        if problem:
            return response(key, None, errors=[problem])
        count = 0
        for rec in records:
            value = rec.get("global_encryption")
            if value is None or value is False or (isinstance(value, str) and value.strip().lower() in OFF):
                count = count + 1
        extra = {"storageContainerCount": len(records)}
        if count:
            return response(key, count, extra, fails=[str(count) + " of " + str(len(records)) + " storage containers have no default encryption"])
        return response(key, 0, extra, passes=["All " + str(len(records)) + " storage containers have default encryption"])
    except Exception as e:
        return response(key, None, errors=["Transformation error: " + str(e)[:200]])
