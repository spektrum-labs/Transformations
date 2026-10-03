"""Transformation: isbackupimmutable_v4 - Commvault (Command Center REST API). Not measured (None) on any body that proves nothing."""
import json
from datetime import datetime


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode") or cur.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the pagination block stays visible and a partial read is caught.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def parse_time(text):
    """Naive-UTC datetime from an ISO-8601 string, or None."""
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        return datetime.fromisoformat(text[:19])
    except Exception:
        return None


def pct(part, whole):
    return round(100.0 * part / whole, 2) if whole else None


VENDOR = "Commvault"


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )


def commvault_error(cur):
    """Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
    if not isinstance(cur, dict):
        return None
    code = cur.get("errorCode")
    if code not in (None, 0, "0"):
        return "Commvault error " + str(code) + ": " + str(cur.get("errorMessage") or cur.get("errorString") or "")[:200]
    errs = cur.get("errList")
    if isinstance(errs, list) and len(errs) > 0:
        return "Commvault errList: " + json.dumps(errs[0])[:200]
    err = cur.get("error")
    if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
        return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")[:200]
    return None


def commvault_box(input, wanted):
    """(container, problem): the dict carrying `wanted` through IS wrappers, or why there is none."""
    body = raw_body(input)
    if isinstance(body, str):
        text = body.strip()
        if text.startswith("<"):
            return None, "Commvault answered with HTML or XML, not JSON (the method must send Accept: application/json)."
    box, problem = find_key(body, wanted)
    if problem is not None:
        return None, problem
    if box is None:
        return None, None
    problem = commvault_error(box)
    if problem is not None:
        return None, problem
    return box, None


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def truthy(value):
    if isinstance(value, bool):
        return value
    n = as_int(value)
    if n is not None:
        return n != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "enabled")
    return False


# Method: getStoragePoolImmutability (workflow)
#   1. GET {serverUrl}/StoragePool -> storagePoolList[].storagePoolEntity.{storagePoolId, storagePoolName}
#   2. GET {serverUrl}/StoragePool/{storagePoolId} per pool, collected under poolDetails[]:
#      storagePoolDetails.isWormStorage, storagePoolDetails.copyInfo.wormStorageFlag (bit flags:
#      1 compliance lock, 2 WORM storage lock, 4 object WORM lock, 8 bucket WORM lock) and
#      storagePoolDetails.copyInfo.copyFlags.wormCopy (1 = compliance lock).
# Source: Commvault's public Python SDK (github.com/Commvault/cvpysdk, cvpysdk/storage_pool.py:
#   StoragePool.is_worm_storage_lock_enabled / is_object_level_worm_lock_enabled / is_compliance_lock_enabled,
#   services STORAGE_POOL "StoragePool" and GET_STORAGE_POOL "StoragePool/%s").
#
# isBackupImmutable = True when at least one storage pool carries a WORM or compliance lock, so an
# immutable copy of the backups exists. False when every pool was read and none is locked.
# None when the pool list or any pool's detail is missing, partial or an error.


def pool_lock(detail):
    """(locked: bool | None, name). None when the detail carries none of the lock fields."""
    if not isinstance(detail, dict):
        return None, None
    spd = detail.get("storagePoolDetails")
    if not isinstance(spd, dict):
        return None, None
    copy_info = spd.get("copyInfo") if isinstance(spd.get("copyInfo"), dict) else {}
    flags = copy_info.get("copyFlags") if isinstance(copy_info.get("copyFlags"), dict) else {}
    entity = spd.get("storagePoolEntity") if isinstance(spd.get("storagePoolEntity"), dict) else {}
    name = entity.get("storagePoolName") or spd.get("storagePoolName")
    seen = False
    locked = False
    if "isWormStorage" in spd:
        seen = True
        locked = locked or truthy(spd.get("isWormStorage"))
    flag = as_int(copy_info.get("wormStorageFlag"))
    if flag is not None:
        seen = True
        locked = locked or flag > 0
    if "wormCopy" in flags:
        seen = True
        locked = locked or as_int(flags.get("wormCopy")) == 1
    if not seen:
        return None, name
    return locked, name


def transform(input):
    key = "isBackupImmutable"
    validation = extract_validation(input)
    box, problem = commvault_box(input, "poolDetails")
    if problem is not None:
        return not_measured(key, "Commvault returned an error instead of the storage pools: " + problem, validation)
    if box is None or not isinstance(box.get("poolDetails"), list):
        return not_measured(key, "No Commvault storage pool details in the response; nothing to evaluate.", validation)
    details = box.get("poolDetails")
    listed = box.get("storagePoolList")
    if not details:
        return not_measured(key, "Commvault returned no storage pools; immutability cannot be judged.", validation)
    if isinstance(listed, list) and len(listed) != len(details):
        return not_measured(key, "Read " + str(len(details)) + " pool details for " + str(len(listed)) + " listed pools; a partial read is not scored.", validation)
    locked_names = []
    open_names = []
    for detail in details:
        problem = commvault_error(detail)
        if problem is not None:
            return not_measured(key, "A storage pool detail read failed: " + problem, validation)
        locked, name = pool_lock(detail)
        if locked is None:
            return not_measured(key, "A storage pool detail carries no WORM or compliance-lock field; immutability cannot be judged.", validation)
        if locked:
            locked_names.append(str(name))
        else:
            open_names.append(str(name))
    ok = len(locked_names) > 0
    text = str(len(locked_names)) + " of " + str(len(details)) + " Commvault storage pools carry a WORM or compliance lock."
    return create_response(
        result={key: ok, "lockedPools": len(locked_names), "totalPools": len(details)},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text],
        recommendations=[] if ok else ["Enable WORM storage lock or compliance lock on at least one storage pool (Command Center > Storage)."],
        input_summary={"lockedPools": locked_names[:25], "unlockedPools": open_names[:25]},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )
