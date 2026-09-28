"""
Transformation: isEncryptionInTransitEnforced
Vendor: Supabase  |  Category: Data Security
Source: GET /v1/projects/{ref}/ssl-enforcement, fanned out across the organization's projects
Pass: every project enforces SSL on database connections and the setting has applied.
Emits sslEnforcementCoveragePercentage as the measured number.
"""
import json
from datetime import datetime


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


def as_list(value):
    """Fan-out steps return a list of per-project responses; single calls return one object."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def unwrap_item(item, *keys):
    """Per-project responses may still carry an apiResponse/data envelope."""
    for _ in range(3):
        if not isinstance(item, dict):
            return {}
        for k in ("apiResponse", "response", "result", "data"):
            inner = item.get(k)
            if isinstance(inner, dict):
                item = inner
                break
        else:
            break
    for k in keys:
        if isinstance(item, dict) and k in item:
            return item
    return item if isinstance(item, dict) else {}


def pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)
def pick_list(data, key):
    """The fan-out step may deliver its list at `key`, or as the whole payload."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get(key, data)
    return []


def evaluate(data):
    items = as_list(pick_list(data, "sslEnforcement"))
    total = len(items)
    enforced, not_applied, unenforced, unreadable = [], [], [], []
    for idx, raw in enumerate(items):
        item = unwrap_item(raw, "currentConfig", "appliedSuccessfully")
        ref = item.get("ref") or item.get("projectRef") or "project[%d]" % idx
        config = item.get("currentConfig")
        if not isinstance(config, dict):
            unreadable.append(ref)
            continue
        if bool(config.get("database")):
            if item.get("appliedSuccessfully") is False:
                not_applied.append(ref)
            else:
                enforced.append(ref)
        else:
            unenforced.append(ref)
    measured = total - len(unreadable)
    coverage = pct(len(enforced), measured)
    result = {
        "isEncryptionInTransitEnforced": measured > 0 and len(enforced) == measured,
        "sslEnforcementCoveragePercentage": coverage,
        "projectsEvaluated": measured,
        "projectsEnforcingSsl": len(enforced),
        "projectsWithoutSsl": unenforced,
        "projectsWithPendingSsl": not_applied,
        "projectsNotMeasured": unreadable,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append(
            "No project returned a readable ssl-enforcement configuration, so encryption "
            "in transit could not be measured."
        )
        recs.append("Confirm the token can read /v1/projects/{ref}/ssl-enforcement for each project.")
    elif len(enforced) == measured:
        passes.append(
            "All %d measured project(s) enforce SSL on database connections "
            "(currentConfig.database = true, applied)." % measured
        )
    else:
        fails.append(
            "%d of %d measured project(s) do not enforce SSL on database connections: %s."
            % (len(unenforced) + len(not_applied), measured,
               ", ".join((unenforced + not_applied)[:10]) or "unnamed")
        )
        recs.append(
            "Enable Enforce SSL on incoming connections under Project Settings > Database "
            "for every project holding production data."
        )
    if unreadable:
        recs.append(
            "%d project(s) returned no ssl-enforcement configuration and are counted as "
            "not measured, never as passing." % len(unreadable)
        )
    return result, passes, fails, recs, {"projectsEvaluated": measured, "responsesReceived": total}


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
            "transformationId": "isEncryptionInTransitEnforced",
            "vendor": "Supabase",
            "category": "Data Security",
        },
    )
