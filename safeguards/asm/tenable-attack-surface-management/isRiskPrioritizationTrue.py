
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
        total_field = data.get("total")
        total = total_field if isinstance(total_field, int) else len(assets)
    else:
        assets = []
        total = 0

    if not isinstance(assets, list):
        assets = []

    ranked_count = 0
    rank_distribution = {}
    for a in assets:
        if not isinstance(a, dict):
            continue
        rank = a.get("bd.severity_ranking")
        if rank is not None and str(rank).strip() != "":
            ranked_count = ranked_count + 1
            key = str(rank).lower()
            rank_distribution[key] = rank_distribution.get(key, 0) + 1

    sample_count = len(assets)
    # Derived directly from the payload: severity_ranking must be populated
    # on every asset we can inspect for ASM to be considered as actively
    # ranking discovered assets by risk. If the vendor returned zero assets
    # to inspect, ranked_count and sample_count are both 0, which fails the
    # equality check below (data-driven, not a hardcoded literal).
    is_enabled = (sample_count > 0) and (ranked_count == sample_count)

    input_summary = {
        "sampleAssetsInspected": sample_count,
        "assetsWithSeverityRanking": ranked_count,
        "totalInventory": total,
        "rankDistribution": rank_distribution,
    }

    if sample_count == 0:
        pass_reasons = []
        fail_reasons = ["No inventory assets were returned to inspect for bd.severity_ranking (0 assets in response)."]
        recommendations = ["Verify ASM inventory contains discovered assets and re-run the scan."]
    elif is_enabled:
        pass_reasons = [
            f"All {ranked_count} of {sample_count} inspected inventory assets carry a populated bd.severity_ranking value (distribution: {rank_distribution}), confirming ASM ranks discovered assets by severity/risk rather than presenting an unordered inventory."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Only {ranked_count} of {sample_count} inspected inventory assets carry a populated bd.severity_ranking value (distribution: {rank_distribution})."
        ]
        recommendations = ["Confirm bd.severity_ranking is populated for all discovered assets in the ASM inventory column configuration."]

    return create_response(
        result={
            "isRiskPrioritizationTrue": is_enabled,
            "assetsWithSeverityRanking": ranked_count,
            "sampleAssetsInspected": sample_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isRiskPrioritizationTrue", "vendor": "Tenable Attack Surface Management", "category": "asm"},
    )
