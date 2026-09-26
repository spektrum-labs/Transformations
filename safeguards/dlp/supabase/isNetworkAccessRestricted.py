"""
Transformation: isNetworkAccessRestricted
Vendor: Supabase  |  Category: Data Security
Source: GET /v1/projects/{ref}/network-restrictions, fanned out across projects
Pass: every project applies a CIDR allow-list that is not open to the internet.
Emits networkRestrictionCoveragePercentage and the count of open projects.
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


def _as_list(value):
    """Fan-out steps return a list of per-project responses; single calls return one object."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _unwrap(item, *keys):
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


def _pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)
def _pick(data, key):
    """The fan-out step may deliver its list at `key`, or as the whole payload."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get(key, data)
    return []


OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def evaluate(data):
    items = _as_list(_pick(data, "networkRestrictions"))
    total = len(items)
    restricted, open_to_internet, unreadable, not_entitled = [], [], [], []
    for idx, raw in enumerate(items):
        item = _unwrap(raw, "config", "status", "entitlement")
        ref = item.get("ref") or item.get("projectRef") or "project[%d]" % idx
        config = item.get("config")
        if not isinstance(config, dict):
            if str(item.get("entitlement", "")).lower() in ("disallowed", "not_entitled"):
                not_entitled.append(ref)
            else:
                unreadable.append(ref)
            continue
        cidrs = []
        for field in ("dbAllowedCidrs", "dbAllowedCidrsV6"):
            value = config.get(field)
            if isinstance(value, list):
                cidrs.extend(str(c) for c in value)
        if not cidrs or any(c in OPEN_CIDRS for c in cidrs):
            open_to_internet.append(ref)
        elif str(item.get("status", "applied")).lower() == "applied":
            restricted.append(ref)
        else:
            open_to_internet.append(ref)
    measured = total - len(unreadable) - len(not_entitled)
    pct = _pct(len(restricted), measured)
    result = {
        "isNetworkAccessRestricted": measured > 0 and len(open_to_internet) == 0,
        "networkRestrictionCoveragePercentage": pct,
        "projectsEvaluated": measured,
        "projectsRestricted": len(restricted),
        "openToInternetProjectCount": len(open_to_internet),
        "openToInternetProjects": open_to_internet[:25],
        "projectsNotEntitled": not_entitled,
        "projectsNotMeasured": unreadable,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append(
            "No project returned a readable network-restrictions configuration, so database "
            "network exposure could not be measured."
        )
    elif not open_to_internet:
        passes.append(
            "All %d measured project(s) apply a CIDR allow-list that is narrower than the "
            "open internet." % measured
        )
    else:
        fails.append(
            "%d of %d measured project(s) accept database connections from any address: %s."
            % (len(open_to_internet), measured, ", ".join(open_to_internet[:10]))
        )
        recs.append(
            "Set an explicit dbAllowedCidrs allow-list under Project Settings > Database > "
            "Network Restrictions for each exposed project."
        )
    if not_entitled:
        recs.append(
            "%d project(s) are on a plan that does not offer network restrictions; they are "
            "counted as not measured. Upgrade the plan or accept the exposure explicitly."
            % len(not_entitled)
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
            "transformationId": "isNetworkAccessRestricted",
            "vendor": "Supabase",
            "category": "Data Security",
        },
    )
