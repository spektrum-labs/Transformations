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
        risks = data
    elif isinstance(data, dict):
        risks = data.get("risks") or []
    else:
        risks = []

    total = len(risks)
    with_severity = 0
    severity_counts = {}
    with_category = 0

    for r in risks:
        if not isinstance(r, dict):
            continue
        sev = r.get("severity")
        if isinstance(sev, str) and sev.strip():
            with_severity = with_severity + 1
            key = sev.strip().lower()
            severity_counts[key] = severity_counts.get(key, 0) + 1
        cat = r.get("category")
        if isinstance(cat, str) and cat.strip():
            with_category = with_category + 1

    is_prioritized = total > 0 and with_severity == total

    severity_summary = ", ".join([f"{k}={v}" for k, v in severity_counts.items()])

    if is_prioritized:
        pass_reasons = [
            f"All {total} findings returned by /risks carry a populated severity field "
            f"(distribution: {severity_summary}), and {with_category} of {total} also carry a "
            f"category, which UpGuard uses to triage remediation order."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Only {with_severity} of {total} findings from /risks carry a populated severity "
            f"field; the remainder lack a value that could be used to prioritize remediation order."
        ]
        recommendations = [
            "Ensure all findings surfaced by the UpGuard /risks endpoint are enriched with a "
            "severity classification before relying on them for remediation triage."
        ] if total > 0 else [
            "No risk findings were returned; confirm the account has active scans producing "
            "risk data before evaluating prioritization."
        ]

    result = {
        "isRiskPrioritizationTrue": is_prioritized,
        "totalFindings": total,
        "findingsWithSeverity": with_severity,
        "findingsWithCategory": with_category,
    }

    input_summary = {
        "totalFindings": total,
        "findingsWithSeverity": with_severity,
        "severityDistribution": severity_counts,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isRiskPrioritizationTrue",
            "vendor": "UpGuard Threat Monitoring Data Leak Protection",
            "category": "asm",
        },
    )
