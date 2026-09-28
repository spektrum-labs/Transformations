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
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
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


# The exact JSON shape Datto EDR / Infocyte's REST API returns for a host list was
# not confirmed from public docs (github.com/Infocyte/extension-docs only documents
# agent-side Lua extensions; the Cortex XSOAR Infocyte integration only confirms
# base URL + auth, not raw REST field names). This tries several plausible field
# names defensively rather than assuming one exact shape — verify against a live
# tenant response and tighten these candidate lists once confirmed.
ENROLLED_FIELD_CANDIDATES = ["enrolled", "isEnrolled", "enabled", "active"]
ONLINE_FIELD_CANDIDATES = ["online", "isOnline", "connected"]
LAST_SCAN_FIELD_CANDIDATES = ["lastScanDate", "lastScan", "lastCheckin", "lastSeen"]
NAME_FIELD_CANDIDATES = ["hostname", "name", "targetName", "computerName"]


def _first_present(d, candidates):
    for key in candidates:
        if isinstance(d, dict) and key in d and d[key] is not None:
            return d[key]
    return None


def _extract_hosts(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["items", "data", "hosts", "targets", "rows", "results"]:
            val = data.get(key)
            if isinstance(val, list):
                return val
    return []


def transform(input):
    data, validation = extract_input(input)

    api_errors = []
    if isinstance(data, dict) and data.get("error"):
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    hosts = _extract_hosts(data)

    total = len(hosts)
    protected = []
    unprotected = []
    unknown = []

    for h in hosts:
        if not isinstance(h, dict):
            continue
        name = _first_present(h, NAME_FIELD_CANDIDATES) or "unknown"
        enrolled = _first_present(h, ENROLLED_FIELD_CANDIDATES)
        if enrolled is None:
            unknown.append(name)
        elif enrolled is True or str(enrolled).strip().lower() in ("true", "1", "yes"):
            protected.append(name)
        else:
            unprotected.append(name)

    is_epp_enabled = total > 0 and len(protected) == total

    input_summary = {
        "totalHosts": total,
        "enrolledHosts": len(protected),
        "notEnrolledHosts": len(unprotected),
        "unknownStatusHosts": len(unknown),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append("No hosts/agents were returned by Datto EDR; cannot confirm enrollment.")
        recommendations.append("Confirm the server URL and API token are correct and that hosts are enrolled in this Datto EDR (Infocyte) instance.")
    elif unknown and not unprotected and len(protected) + len(unknown) == total:
        fail_reasons.append(
            "Could not determine enrollment status for %d of %d hosts (e.g. %s) — the response did not carry a recognized status field."
            % (len(unknown), total, ", ".join(unknown[:5]))
        )
        recommendations.append("Confirm the exact field name Datto EDR returns for host enrollment/agent status and update this transformation's ENROLLED_FIELD_CANDIDATES.")
    elif is_epp_enabled:
        pass_reasons.append("All %d hosts are enrolled and reporting to Datto EDR." % total)
    else:
        names = ", ".join(unprotected[:5])
        fail_reasons.append(
            "%d of %d hosts are not enrolled/protected (e.g. %s)."
            % (len(unprotected), total, names)
        )
        recommendations.append("Deploy or re-enroll the Datto EDR agent on all endpoints that are not currently reporting.")

    result = {
        "isEPPEnabled": is_epp_enabled,
        "totalHosts": total,
        "enrolledHosts": len(protected),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "Kaseya Datto EDR",
            "category": "epp",
        },
    )
