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


VALID_RANKINGS = ["critical", "high", "medium", "low", "none"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        assets = data
        total = len(assets)
    else:
        assets = data.get("assets") or []
        total = data.get("total") or len(assets)

    ranking_counts = {}
    assets_with_ranking = 0
    distinct_rankings = set()

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        ranking = asset.get("bd.severity_ranking")
        if ranking is not None and ranking != "":
            assets_with_ranking = assets_with_ranking + 1
            distinct_rankings.add(ranking)
            ranking_counts[ranking] = (ranking_counts.get(ranking) or 0) + 1

    sample_size = len(assets)
    has_recognized_rankings = any(r in VALID_RANKINGS for r in distinct_rankings)
    is_enabled = sample_size > 0 and assets_with_ranking > 0 and has_recognized_rankings

    counts_str = ", ".join([f"{k}={v}" for k, v in ranking_counts.items()])

    if is_enabled:
        pass_reasons = [
            f"bd.severity_ranking is populated on {assets_with_ranking} of {sample_size} sampled inventory assets, "
            f"with recognized severity values ({counts_str}), evidencing risk-based ranking of discovered assets."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"bd.severity_ranking was not populated with recognized severity values across the {sample_size} "
            f"sampled inventory assets (assets_with_ranking={assets_with_ranking})."
        ]
        recommendations = [
            "Verify the ASM inventory is configured to compute severity_ranking on discovered assets, "
            "or check that the inventory columns request includes bd.severity_ranking."
        ]

    result = {
        "isRiskPrioritizationTrue": is_enabled,
        "totalAssetsSampled": sample_size,
        "assetsWithSeverityRanking": assets_with_ranking,
        "severityRankingDistribution": ranking_counts,
    }

    input_summary = {
        "totalAssetsInInventory": total,
        "sampleSize": sample_size,
        "assetsWithRanking": assets_with_ranking,
        "distinctRankingValues": list(distinct_rankings),
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
