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


ATTRIBUTION_FIELDS = [
    "bd.original_hostname",
    "bd.severity_ranking",
    "bd.hostname",
    "bd.record_type",
    "bd.ip_address",
    "bd.addedtoportfolio",
    "bd.last_metadata_change",
]

BUSINESS_UNIT_FIELD = "bd.smartfolders"


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        assets = data
        total_reported = len(assets)
    elif isinstance(data, dict):
        assets = data.get("assets") or []
        total_reported = data.get("total") or len(assets)
    else:
        assets = []
        total_reported = 0

    if not isinstance(assets, list):
        assets = []

    total_assets = len(assets)

    def is_populated(v):
        if v is None:
            return False
        if isinstance(v, str) and v.strip() == "":
            return False
        return True

    assets_with_attribution = 0
    assets_with_business_unit = 0
    field_populated_counts = {}
    for f in ATTRIBUTION_FIELDS:
        field_populated_counts[f] = 0

    for a in assets:
        if not isinstance(a, dict):
            continue
        has_any = False
        for f in ATTRIBUTION_FIELDS:
            if is_populated(a.get(f)):
                field_populated_counts[f] = field_populated_counts[f] + 1
                has_any = True
        if has_any:
            assets_with_attribution = assets_with_attribution + 1
        if is_populated(a.get(BUSINESS_UNIT_FIELD)):
            assets_with_business_unit = assets_with_business_unit + 1

    if total_assets > 0:
        attribution_pct = (assets_with_attribution / total_assets) * 100.0
        business_unit_pct = (assets_with_business_unit / total_assets) * 100.0
    else:
        attribution_pct = 0.0
        business_unit_pct = 0.0

    is_enabled = total_assets > 0 and attribution_pct >= 80.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            "%d of %d inventory assets (%.1f%%) carry populated bd.* attribution fields "
            "such as bd.original_hostname and bd.severity_ranking (both 100%% populated in the "
            "field census), evidencing business-division attribution linkage." % (
                assets_with_attribution, total_assets, attribution_pct
            )
        )
        if business_unit_pct == 0.0:
            recommendations.append(
                "bd.smartfolders (the dedicated business-unit grouping column) is present on all "
                "assets but populated on 0%% of them - consider assigning assets to smart folders "
                "to strengthen business-unit-level attribution beyond hostname/severity metadata."
            )
    else:
        fail_reasons.append(
            "Only %d of %d inventory assets (%.1f%%) carry populated bd.* attribution fields, "
            "and bd.smartfolders (business-unit grouping) is populated on %.1f%% of assets." % (
                assets_with_attribution, total_assets, attribution_pct, business_unit_pct
            )
        )
        recommendations.append(
            "Populate bd.* business-division fields (e.g. bd.smartfolders, bd.original_hostname) "
            "on discovered assets via Tenable ASM smart folders or metadata mapping to enable "
            "business-division attribution."
        )

    result = {
        "isBusinessDivisionAttributionEnabled": is_enabled,
        "totalAssets": total_assets,
        "assetsWithAttribution": assets_with_attribution,
        "attributionPercentage": round(attribution_pct, 1),
        "assetsWithBusinessUnitTag": assets_with_business_unit,
        "businessUnitTagPercentage": round(business_unit_pct, 1),
    }

    input_summary = {
        "totalAssetsReported": total_reported,
        "totalAssetsInResponse": total_assets,
        "fieldPopulatedCounts": field_populated_counts,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBusinessDivisionAttributionEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
