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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        alerts = data
    elif isinstance(data, dict):
        alerts = data.get("data") or data.get("apiResponse") or []
        if not isinstance(alerts, list):
            alerts = []
    else:
        alerts = []

    open_alerts = [a for a in alerts if isinstance(a, dict) and a.get("state") == "open"]
    open_count = len(open_alerts)

    secret_types = {}
    repos = {}
    for a in open_alerts:
        st = a.get("secret_type") or "unknown"
        secret_types[st] = secret_types.get(st, 0) + 1
        repo = a.get("repository") or {}
        repo_name = repo.get("full_name") if isinstance(repo, dict) else None
        if repo_name:
            repos[repo_name] = repos.get(repo_name, 0) + 1

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if open_count == 0:
        pass_reasons.append(
            "No open secret scanning alerts found across org repositories "
            "(state=open filter applied at the API query level)."
        )
    else:
        top_types = sorted(secret_types.items(), key=lambda kv: -kv[1])[:5]
        type_summary = ", ".join([f"{t}: {c}" for t, c in top_types])
        fail_reasons.append(
            f"Found {open_count} open secret scanning alerts across "
            f"{len(repos)} repositories. Top secret types: {type_summary}."
        )
        recommendations.append(
            "Review and remediate the flagged secrets (rotate/revoke credentials) "
            "and resolve the corresponding secret scanning alerts in the affected repositories."
        )

    result = {
        "openSecretScanningAlertsCount": open_count,
        "affectedRepositoryCount": len(repos),
        "secretTypeBreakdown": secret_types,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalAlertsInResponse": len(alerts), "openAlertsCounted": open_count},
        metadata={
            "transformationId": "openSecretScanningAlertsCount",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
