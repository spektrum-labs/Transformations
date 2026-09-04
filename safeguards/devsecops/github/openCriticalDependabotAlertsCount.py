import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or data.get("apiResponse") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    # Defensively re-check state/severity in case the vendor filter was not
    # fully applied server-side; count only records that truly match.
    matched = []
    for alert in items:
        if not isinstance(alert, dict):
            continue
        state = alert.get("state")
        sev = None
        vuln = alert.get("security_vulnerability")
        if isinstance(vuln, dict):
            sev = vuln.get("severity")
        if state == "open" and sev == "critical":
            matched.append(alert)

    # Some records may lack security_vulnerability details due to
    # truncation of nested fields in captured samples; if state is open
    # and severity info is entirely absent, still count it since the
    # request itself was filtered to severity=critical server-side.
    unverifiable_but_open = [
        a for a in items
        if isinstance(a, dict) and a.get("state") == "open"
        and not isinstance(a.get("security_vulnerability"), dict)
    ]

    count = len(matched) + len(unverifiable_but_open)

    repos = set()
    for a in matched + unverifiable_but_open:
        repo = a.get("repository")
        if isinstance(repo, dict):
            full_name = repo.get("full_name")
            if full_name:
                repos.add(full_name)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if count == 0:
        pass_reasons.append(
            "No open critical-severity Dependabot alerts were found in the "
            "org-level listing filtered to state=open and severity=critical."
        )
    else:
        fail_reasons.append(
            f"{count} open critical-severity Dependabot alerts found across "
            f"{len(repos)} repositories (e.g. {', '.join(list(repos)[:5])})."
        )
        recommendations.append(
            "Triage and remediate the open critical-severity Dependabot alerts "
            "by upgrading affected dependencies to the patched versions listed "
            "in each alert's security_advisory/security_vulnerability data."
        )

    result = {
        "openCriticalDependabotAlertsCount": count,
        "affectedRepositoryCount": len(repos),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"recordsInResponse": len(items), "matchedCount": count},
        metadata={
            "transformationId": "openCriticalDependabotAlertsCount",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
