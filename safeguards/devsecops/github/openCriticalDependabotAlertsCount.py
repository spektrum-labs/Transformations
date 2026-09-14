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
        alerts = data.get("data") or data.get("alerts") or data.get("apiResponse") or []
        if not isinstance(alerts, list):
            alerts = []
    else:
        alerts = []

    critical_open_count = 0
    repos_affected = {}
    ecosystems = {}

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        state = alert.get("state")
        vuln = alert.get("security_vulnerability") or {}
        severity = vuln.get("severity") if isinstance(vuln, dict) else None
        if state == "open" and severity == "critical":
            critical_open_count = critical_open_count + 1
            repo = alert.get("repository") or {}
            repo_name = repo.get("full_name") if isinstance(repo, dict) else None
            if repo_name:
                repos_affected[repo_name] = True
            dep = alert.get("dependency") or {}
            pkg = dep.get("package") or {} if isinstance(dep, dict) else {}
            eco = pkg.get("ecosystem") if isinstance(pkg, dict) else None
            if eco:
                ecosystems[eco] = True

    total_records = len(alerts)
    distinct_repos = len(repos_affected.keys())
    distinct_ecosystems = len(ecosystems.keys())

    if critical_open_count > 0:
        pass_reasons = []
        fail_reasons = [
            f"Found {critical_open_count} open critical-severity Dependabot alerts across {distinct_repos} repositories (ecosystems: {distinct_ecosystems})."
        ]
        recommendations = [
            "Prioritize remediation of open critical Dependabot alerts by upgrading affected dependencies to their first_patched_version."
        ]
    else:
        pass_reasons = [
            f"No open critical-severity Dependabot alerts found among {total_records} records returned by the org-level Dependabot alerts API filtered to state=open and severity=critical."
        ]
        fail_reasons = []
        recommendations = []

    return create_response(
        result={
            "openCriticalDependabotAlertsCount": critical_open_count,
            "distinctRepositoriesAffected": distinct_repos,
            "distinctEcosystemsAffected": distinct_ecosystems,
            "totalRecordsReturned": total_records,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalRecordsReturned": total_records,
            "criticalOpenCount": critical_open_count,
        },
        metadata={
            "transformationId": "openCriticalDependabotAlertsCount",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
