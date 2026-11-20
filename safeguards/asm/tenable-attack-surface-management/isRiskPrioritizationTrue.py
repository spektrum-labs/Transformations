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
    elif isinstance(data, dict):
        assets = data.get("assets") or data.get("data") or []
    else:
        assets = []

    total_assets = len(assets)

    valid_rankings = {"critical", "high", "medium", "low", "none"}
    ranked_count = 0
    ranking_counts = {}
    for a in assets:
        if not isinstance(a, dict):
            continue
        ranking = a.get("bd.severity_ranking")
        if isinstance(ranking, str) and ranking.strip() != "":
            ranked_count = ranked_count + 1
            key = ranking.strip().lower()
            ranking_counts[key] = ranking_counts.get(key, 0) + 1

    # Consider risk prioritization enabled if a clear majority of assets
    # carry a recognized severity_ranking value.
    coverage_ratio = (ranked_count / total_assets) if total_assets > 0 else 0.0
    has_recognized_values = any(k in valid_rankings for k in ranking_counts.keys())
    is_enabled = total_assets > 0 and coverage_ratio >= 0.9 and has_recognized_values

    input_summary = {
        "totalAssets": total_assets,
        "assetsWithSeverityRanking": ranked_count,
        "severityRankingCoverageRatio": round(coverage_ratio, 4),
        "severityRankingBreakdown": ranking_counts,
    }

    if is_enabled:
        pass_reasons = [
            f"{ranked_count} of {total_assets} assets ({round(coverage_ratio * 100, 1)}%) "
            f"carry a populated bd.severity_ranking value with breakdown {ranking_counts}, "
            "showing Tenable ASM's built-in risk ranking is actively applied to discovered assets."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_assets == 0:
            fail_reasons = ["No assets were returned by the inventory search, so severity_ranking coverage could not be evaluated."]
        else:
            fail_reasons = [
                f"Only {ranked_count} of {total_assets} assets ({round(coverage_ratio * 100, 1)}%) "
                f"carry a recognized bd.severity_ranking value (breakdown {ranking_counts}); "
                "risk prioritization does not appear consistently applied across the inventory."
            ]
        recommendations = [] if total_assets == 0 else [
            "Ensure severity_ranking metadata is populated across the asset inventory so ASM findings are ranked by risk."
        ]

    result = {
        "isRiskPrioritizationTrue": is_enabled,
        "totalAssets": total_assets,
        "assetsWithSeverityRanking": ranked_count,
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
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
