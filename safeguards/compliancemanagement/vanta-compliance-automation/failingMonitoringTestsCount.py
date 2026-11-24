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
        tests = data
    elif isinstance(data, dict):
        results = data.get("results") or {}
        if isinstance(results, dict):
            tests = results.get("data") or []
        elif isinstance(results, list):
            tests = results
        else:
            tests = data.get("data") or []
    else:
        tests = []

    if not isinstance(tests, list):
        tests = []

    needs_attention = []
    status_counts = {}
    for t in tests:
        if not isinstance(t, dict):
            continue
        status = t.get("status") or "UNKNOWN"
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == "NEEDS_ATTENTION":
            needs_attention.append(t)

    failing_count = len(needs_attention)
    total_tests = len(tests)

    sample_names = [t.get("name") or t.get("id") for t in needs_attention[:5]]

    if failing_count > 0:
        pass_reasons = []
        fail_reasons = [
            f"{failing_count} of {total_tests} Vanta tests are in NEEDS_ATTENTION status. "
            f"Examples: {', '.join([str(n) for n in sample_names if n])}."
        ]
        recommendations = [
            "Review and remediate the failing Vanta tests listed in failReasons, "
            "prioritizing those tied to monitoring/security controls."
        ]
    else:
        pass_reasons = [
            f"All {total_tests} Vanta tests evaluated report a status other than NEEDS_ATTENTION "
            f"(status breakdown: {status_counts})."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "failingMonitoringTestsCount": failing_count,
        "totalTestsEvaluated": total_tests,
        "statusBreakdown": status_counts,
    }

    input_summary = {
        "totalTests": total_tests,
        "failingTests": failing_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "failingMonitoringTestsCount",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
    )
