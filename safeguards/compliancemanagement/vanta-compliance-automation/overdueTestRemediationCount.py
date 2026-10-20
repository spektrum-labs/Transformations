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

    overdue_tests = []
    failing_tests = []
    api_errors = []

    for t in tests:
        if not isinstance(t, dict):
            continue
        status = t.get("status")
        if status and status != "OK":
            failing_tests.append(t)
        remediation_info = t.get("remediationStatusInfo") or {}
        if isinstance(remediation_info, dict):
            rem_status = remediation_info.get("status")
            if rem_status == "OVERDUE":
                overdue_tests.append(t)

    overdue_count = len(overdue_tests)
    total_tests = len(tests)

    sample_names = [t.get("name") or t.get("id") for t in overdue_tests[:5]]

    if overdue_count > 0:
        pass_reasons = [
            f"Found {overdue_count} of {total_tests} tests with remediationStatusInfo.status == 'OVERDUE'. "
            f"Examples: {', '.join([str(n) for n in sample_names if n])}."
        ]
        fail_reasons = []
        recommendations = [
            "Review and remediate the overdue failing tests listed above to bring them back into compliance before their SLA deadlines."
        ]
    else:
        pass_reasons = [
            f"No tests out of {total_tests} total carry remediationStatusInfo.status == 'OVERDUE'."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "overdueTestRemediationCount": overdue_count,
        "totalTestsEvaluated": total_tests,
        "failingTestsCount": len(failing_tests),
    }

    input_summary = {
        "totalTests": total_tests,
        "failingTests": len(failing_tests),
        "overdueTests": overdue_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "overdueTestRemediationCount",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
        api_errors=api_errors,
    )
