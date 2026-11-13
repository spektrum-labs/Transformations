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
        total_reported = len(assets)
    elif isinstance(data, dict):
        assets = data.get("assets") or []
        total_reported = data.get("total") if data.get("total") is not None else len(assets)
    else:
        assets = []
        total_reported = 0

    high_assets = []
    for a in assets:
        if not isinstance(a, dict):
            continue
        sev = a.get("bd.severity_ranking")
        if isinstance(sev, str) and sev.strip().lower() == "high":
            high_assets.append(a)

    high_count = len(high_assets)
    no_high_findings = high_count == 0

    sample_ids = [a.get("id") for a in high_assets[:5]]

    input_summary = {
        "totalAssetsScanned": len(assets),
        "totalReportedByVendor": total_reported,
        "highSeverityCount": high_count,
    }

    if no_high_findings:
        pass_reasons = [
            f"Scanned {len(assets)} inventory assets (vendor-reported total {total_reported}); "
            f"no assets carry bd.severity_ranking='high'."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Found {high_count} asset(s) with bd.severity_ranking='high' out of {len(assets)} scanned "
            f"(vendor-reported total {total_reported}). Example asset ids: {sample_ids}."
        ]
        recommendations = [
            "Review and remediate the high-severity assets in Tenable ASM inventory, "
            "or reclassify/portfolio them once confirmed benign."
        ]

    return create_response(
        result={
            "noHighFindings": no_high_findings,
            "highFindingsCount": high_count,
            "totalAssetsScanned": len(assets),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "noHighFindings",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
