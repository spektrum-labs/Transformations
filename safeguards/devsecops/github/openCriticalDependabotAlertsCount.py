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
        alerts = data
    elif isinstance(data, dict):
        alerts = data.get("data") or data.get("alerts") or []
        if not isinstance(alerts, list):
            alerts = []
    else:
        alerts = []

    open_critical = []
    repos_affected = {}
    for a in alerts:
        if not isinstance(a, dict):
            continue
        state = a.get("state")
        advisory = a.get("security_advisory") or {}
        severity = advisory.get("severity")
        if severity is None:
            severity = a.get("severity")
        if state == "open" and severity == "critical":
            open_critical.append(a)
            repo = (a.get("repository") or {}).get("full_name") or "unknown"
            repos_affected[repo] = repos_affected.get(repo, 0) + 1
        elif state == "open" and severity is None:
            open_critical.append(a)
            repo = (a.get("repository") or {}).get("full_name") or "unknown"
            repos_affected[repo] = repos_affected.get(repo, 0) + 1

    count = len(open_critical)

    repo_list = sorted(repos_affected.keys())
    top_repos = repo_list[:5]

    if count == 0:
        pass_reasons = ["No open critical Dependabot alerts were found in the organization's alert feed (state=open, severity=critical filter)."]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{count} open critical Dependabot alerts found across {len(repo_list)} repositories, e.g. {', '.join(top_repos)}."
        ]
        recommendations = [
            "Triage and remediate open critical Dependabot alerts by upgrading affected dependencies or applying vendor-recommended patches.",
        ]

    result = {
        "openCriticalDependabotAlertsCount": count,
        "affectedRepositoryCount": len(repo_list),
    }

    input_summary = {
        "totalAlertsInResponse": len(alerts),
        "openCriticalAlerts": count,
        "affectedRepositories": len(repo_list),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "openCriticalDependabotAlertsCount",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
