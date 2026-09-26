"""
Transformation: isControllerFirmwareTracked
Vendor: acre Access Control  |  Category: Physical Security
Source: GET /api/f/{instanceKey}/controllers, reading Version and Status.NeedsDbPush
Pass: every enabled controller reports a firmware version and has no pending database
push. A controller that has not taken its database push is enforcing stale access rights.
"""
import json
from datetime import datetime, timezone


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
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


def pick_list(data, *keys):
    """The collection may arrive at a named key, or as the whole payload."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            value = data.get(k)
            if isinstance(value, list):
                return value
        for k in ("items", "value", "results", "resources"):
            value = data.get(k)
            if isinstance(value, list):
                return value
    return []


def pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)


def field_value(record, *names):
    """Field casing varies between the REST payload and the BSON projection."""
    for n in names:
        if n in record:
            return record[n]
        alt = n[0].lower() + n[1:]
        if alt in record:
            return record[alt]
    return None


def parse_dt(value):
    if not value or not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(value[:19], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def utc_now():
    return datetime.now(timezone.utc)


def evaluate(data):
    controllers = pick_list(data, "controllers")
    enabled = [c for c in controllers if not field_value(c, "IsDisabled")]
    versioned, unversioned, pending_push = [], [], []
    versions = {}
    for c in enabled:
        name = field_value(c, "CommonName") or field_value(c, "Key") or "unnamed"
        version = field_value(c, "Version")
        if version:
            versioned.append(name)
            versions[str(version)] = versions.get(str(version), 0) + 1
        else:
            unversioned.append(name)
        status = field_value(c, "Status") or {}
        status = status if isinstance(status, dict) else {}
        if field_value(status, "NeedsDbPush"):
            pending_push.append(name)
    measured = len(enabled)
    result = {
        "isControllerFirmwareTracked": measured > 0 and not unversioned and not pending_push,
        "firmwareVisibilityPercentage": pct(len(versioned), measured),
        "controllersEvaluated": measured,
        "controllersWithoutVersionCount": len(unversioned),
        "controllersPendingDatabasePushCount": len(pending_push),
        "controllersPendingDatabasePush": pending_push[:25],
        "firmwareVersionSpread": versions,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append("No enabled controller was returned, so firmware tracking could not be measured.")
    elif not unversioned and not pending_push:
        passes.append(
            "All %d enabled controller(s) report a firmware version and none has a pending "
            "database push." % measured
        )
        if len(versions) > 1:
            recs.append(
                "The estate runs %d distinct firmware versions. A mixed estate means a "
                "patched vulnerability is only patched on part of it." % len(versions)
            )
    else:
        if unversioned:
            fails.append(
                "%d of %d enabled controller(s) report no firmware version, so their patch "
                "level is unknown." % (len(unversioned), measured)
            )
        if pending_push:
            fails.append(
                "%d controller(s) have a pending database push and are enforcing stale "
                "access rights." % len(pending_push)
            )
            recs.append("Complete the pending database pushes so revoked credentials stop working at the door.")
    return result, passes, fails, recs, {"controllersEvaluated": measured},


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    result, pass_reasons, fail_reasons, recommendations, input_summary = evaluate(data)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isControllerFirmwareTracked",
            "vendor": "Acre Security",
            "category": "Physical Security",
        },
    )
