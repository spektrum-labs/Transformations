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
        assets = data
        total = len(assets)
    elif isinstance(data, dict):
        assets = data.get("assets") or []
        total = data.get("total")
        if not isinstance(total, int):
            total = len(assets)
    else:
        assets = []
        total = 0

    critical_assets = []
    for a in assets:
        if not isinstance(a, dict):
            continue
        severity = a.get("bd.severity_ranking")
        if isinstance(severity, str) and severity.strip().lower() == "critical":
            critical_assets.append(a)

    critical_count = len(critical_assets)
    no_critical = critical_count == 0

    input_summary = {
        "totalAssetsEvaluated": len(assets),
        "reportedTotal": total,
        "criticalFindingsCount": critical_count,
    }

    if no_critical:
        pass_reasons = [
            f"Scanned {len(assets)} inventory assets (reported total {total}); none carry bd.severity_ranking='critical'."
        ]
        fail_reasons = []
        recommendations = []
    else:
        sample_ids = [a.get("id") for a in critical_assets[:5] if isinstance(a, dict)]
        pass_reasons = []
        fail_reasons = [
            f"{critical_count} of {len(assets)} scanned inventory assets (reported total {total}) carry bd.severity_ranking='critical'. Example asset ids: {sample_ids}."
        ]
        recommendations = [
            "Triage and remediate the critical-severity assets in the ASM inventory, or reclassify them if the risk has been accepted, then re-run discovery."
        ]

    return create_response(
        result={
            "noCriticalFindings": no_critical,
            "criticalFindingsCount": critical_count,
            "totalAssetsEvaluated": len(assets),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "noCriticalFindings",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
