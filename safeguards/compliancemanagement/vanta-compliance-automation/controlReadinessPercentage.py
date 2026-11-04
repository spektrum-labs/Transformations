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
        frameworks = data
    elif isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, dict):
            frameworks = results.get("data") or []
        elif isinstance(results, list):
            frameworks = results
        else:
            frameworks = data.get("data") or []
    else:
        frameworks = []

    if not isinstance(frameworks, list):
        frameworks = []

    total_completed = 0
    total_controls = 0
    per_framework = []
    api_errors = []

    for fw in frameworks:
        if not isinstance(fw, dict):
            continue
        completed = fw.get("numControlsCompleted")
        total = fw.get("numControlsTotal")
        if not isinstance(completed, int) or not isinstance(total, int):
            continue
        total_completed = total_completed + completed
        total_controls = total_controls + total
        per_framework.append({
            "id": fw.get("id"),
            "displayName": fw.get("displayName"),
            "numControlsCompleted": completed,
            "numControlsTotal": total,
        })

    if total_controls > 0:
        percentage = round((total_completed / total_controls) * 100.0, 2)
    else:
        percentage = 0.0
        api_errors.append("No frameworks with valid numControlsTotal found in response")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_controls > 0:
        detail = ", ".join([
            f"{f.get('displayName')}: {f.get('numControlsCompleted')}/{f.get('numControlsTotal')}"
            for f in per_framework
        ])
        pass_reasons.append(
            f"Control readiness computed as {total_completed} of {total_controls} total in-scope controls "
            f"completed across {len(per_framework)} framework(s) ({detail}), yielding {percentage}%."
        )
        if percentage < 100.0:
            recommendations.append(
                f"Complete the remaining {total_controls - total_completed} controls across tracked frameworks "
                "to reach full control readiness."
            )
    else:
        fail_reasons.append(
            "No framework records with numeric numControlsCompleted/numControlsTotal were found in the "
            "GET /v1/frameworks response; control readiness could not be computed."
        )
        recommendations.append(
            "Verify at least one framework is active in Vanta and that GET /v1/frameworks returns "
            "numControlsCompleted/numControlsTotal fields."
        )

    return create_response(
        result={
            "controlReadinessPercentage": percentage,
            "totalControlsCompleted": total_completed,
            "totalControlsInScope": total_controls,
            "frameworkCount": len(per_framework),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "frameworkCount": len(per_framework),
            "totalControlsCompleted": total_completed,
            "totalControlsInScope": total_controls,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "controlReadinessPercentage",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
    )
