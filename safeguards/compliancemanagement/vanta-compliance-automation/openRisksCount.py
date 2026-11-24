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

    api_errors = []
    items = []

    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, dict):
            items = results.get("data") or []
        elif isinstance(data.get("data"), (list, dict)):
            maybe = data.get("data")
            items = maybe if isinstance(maybe, list) else []
        else:
            items = []
    elif isinstance(data, list):
        items = data
    else:
        items = []
        api_errors.append("Unrecognized response shape for getIssues: expected dict or list")

    items = items if isinstance(items, list) else []

    closed_statuses = set([
        "RESOLVED", "CLOSED", "ARCHIVED", "ACCEPTED",
        "RESOLVED_ACCEPTED", "REMEDIATED", "DISMISSED", "RISK_ACCEPTED",
    ])

    open_risk_items = []
    total_risk_items = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        source = (it.get("source") or "")
        itype = (it.get("type") or "")
        status = (it.get("status") or "")
        source_u = source.upper() if isinstance(source, str) else ""
        itype_u = itype.upper() if isinstance(itype, str) else ""
        status_u = status.upper() if isinstance(status, str) else ""

        is_risk = ("RISK" in source_u) or ("RISK" in itype_u)
        if is_risk:
            total_risk_items = total_risk_items + 1
            is_open = (status_u not in closed_statuses) and (status_u != "")
            if is_open:
                open_risk_items.append(it)

    open_count = len(open_risk_items)
    total_issues = len(items)

    sample_names = [str(it.get("name") or it.get("id") or "unnamed") for it in open_risk_items[:5]]

    if total_issues == 0:
        pass_reasons = [
            "The getIssues feed returned 0 total issue records for this tenant, so there are 0 open risk scenarios to report."
        ]
        fail_reasons = []
        recommendations = []
    elif open_count == 0:
        pass_reasons = [
            f"Scanned {total_issues} issue records from getIssues; {total_risk_items} were risk-sourced (source or type containing RISK), and none had a status outside {sorted(closed_statuses)}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Found {open_count} open, non-archived risk scenario(s) out of {total_risk_items} risk-sourced issues (of {total_issues} total issues). Sample: {', '.join(sample_names)}."
        ]
        recommendations = [
            "Review and treat or formally accept the open risk scenarios listed in the risk register so their status moves to resolved or accepted."
        ]

    result = {
        "openRisksCount": open_count,
        "totalRiskSourcedIssues": total_risk_items,
        "totalIssuesScanned": total_issues,
    }

    input_summary = {
        "totalIssuesScanned": total_issues,
        "totalRiskSourcedIssues": total_risk_items,
        "openRisksCount": open_count,
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
            "transformationId": "openRisksCount",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
    )
