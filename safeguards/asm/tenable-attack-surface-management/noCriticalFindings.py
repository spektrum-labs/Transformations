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

    critical_ids = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        severity = asset.get("bd.severity_ranking") or ""
        if isinstance(severity, str) and severity.strip().lower() == "critical":
            asset_id = asset.get("id") or "unknown-id"
            critical_ids.append(asset_id)

    critical_count = len(critical_ids)
    no_critical_findings = critical_count == 0

    input_summary = {
        "totalAssetsReturned": len(assets),
        "totalAssetsReported": total,
        "criticalFindingsCount": critical_count,
    }

    if no_critical_findings:
        pass_reasons = [
            f"Scanned {len(assets)} inventory assets (bd.severity_ranking column) and found 0 with severity_ranking='critical'."
        ]
        fail_reasons = []
        recommendations = []
    else:
        sample_ids = critical_ids[:5]
        pass_reasons = []
        fail_reasons = [
            f"Found {critical_count} asset(s) with bd.severity_ranking='critical' out of {len(assets)} inventory assets scanned (sample IDs: {sample_ids})."
        ]
        recommendations = [
            "Triage and remediate the critical-severity assets identified in the ASM inventory (e.g. by adding them to a smart folder / portfolio and tracking remediation to closure)."
        ]

    result = {
        "noCriticalFindings": no_critical_findings,
        "criticalFindingsCount": critical_count,
        "totalAssetsScanned": len(assets),
    }

    return create_response(
        result=result,
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
