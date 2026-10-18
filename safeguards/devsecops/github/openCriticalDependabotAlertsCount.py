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
    alerts = None
    if isinstance(data, list):
        alerts = data
    elif isinstance(data, dict):
        for key in ("data", "alerts"):
            if isinstance(data.get(key), list):
                alerts = data.get(key)
                break

    # A body that is not a list of alerts (an error envelope, an unexpected shape) is
    # a failed read. Counting it as zero open critical alerts would be a false pass.
    if alerts is None:
        return create_response(
            result={"openCriticalDependabotAlertsCount": None},
            validation=validation,
            fail_reasons=["The Dependabot alerts response was not a list of alerts, so open critical alerts cannot be counted."],
            input_summary={"responseIsList": False},
            api_errors=["Unexpected response shape from /orgs/{org}/dependabot/alerts."],
            metadata={"transformationId": "openCriticalDependabotAlertsCount", "vendor": "GitHub", "category": "devsecops"},
        )

    open_critical = []
    for a in alerts:
        if not isinstance(a, dict):
            continue
        state = a.get("state")
        sev = None
        sec_vuln = a.get("security_vulnerability")
        if isinstance(sec_vuln, dict):
            sev = sec_vuln.get("severity")
        if state == "open" and sev == "critical":
            open_critical.append(a)

    count = len(open_critical)

    # Truncation guard. The organization Dependabot alerts endpoint advertises
    # its next page only in a Link header, which the pagination handler cannot
    # read, so this method fetches a single page of PAGE_SIZE and stops. A
    # response holding exactly PAGE_SIZE alerts means there may be more we
    # cannot see, and a count taken from it would understate the backlog.
    # Report that as a collection error rather than a confident number.
    # Remove once ENG-577 lands real cursor pagination.
    PAGE_SIZE = 100
    if len(alerts) >= PAGE_SIZE:
        return create_response(
            result={"openCriticalDependabotAlertsCount": None, "truncated": True},
            validation=validation,
            fail_reasons=[
                f"Received exactly {len(alerts)} alerts, the maximum this method can fetch in one page, "
                "so the open critical backlog cannot be counted completely. "
                "Pagination for this endpoint is tracked in ENG-577."
            ],
            recommendations=["No customer action required; this is a retrieval limitation on our side."],
            input_summary={"alertsReceived": len(alerts), "pageSize": PAGE_SIZE, "truncated": True},
            api_errors=["Result set truncated at one page; next-page cursor is only available in the Link header."],
            metadata={"transformationId": "openCriticalDependabotAlertsCount", "vendor": "GitHub", "category": "devsecops"},
        )

    repos = set()
    packages = set()
    for a in open_critical:
        dep = a.get("dependency")
        if isinstance(dep, dict):
            pkg = dep.get("package")
            if isinstance(pkg, dict) and pkg.get("name"):
                packages.add(pkg.get("name"))
        repo = a.get("repository")
        if isinstance(repo, dict) and repo.get("full_name"):
            repos.add(repo.get("full_name"))

    sample_numbers = [a.get("number") for a in open_critical[:5] if a.get("number") is not None]

    if count == 0:
        pass_reasons = [
            "Queried /orgs/{org}/dependabot/alerts?state=open&severity=critical and found 0 alerts matching state=open and severity=critical among the returned records."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Found {count} open critical-severity Dependabot alerts across the organization (alert numbers sample: {sample_numbers}).",
        ]
        if packages:
            fail_reasons.append(f"Affected packages include: {sorted(list(packages))[:10]}.")
        recommendations = [
            "Prioritize remediation of critical Dependabot alerts by upgrading affected packages to their first_patched_version.",
            "Review and merge outstanding Dependabot security update pull requests for the affected repositories.",
        ]

    result = {
        "openCriticalDependabotAlertsCount": count,
        "affectedRepositoryCount": len(repos),
        "affectedPackageCount": len(packages),
    }

    input_summary = {
        "totalRecordsInResponse": len(alerts),
        "openCriticalCount": count,
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
