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
        if not isinstance(assets, list):
            assets = []
        total_reported = data.get("total")
        if not isinstance(total_reported, int):
            total_reported = len(assets)
    else:
        assets = []
        total_reported = 0

    total_assets = len(assets)

    tagged_count = 0
    portfolio_count = 0
    for a in assets:
        if not isinstance(a, dict):
            continue
        smartfolders = a.get("bd.smartfolders")
        if isinstance(smartfolders, str) and smartfolders.strip() != "":
            tagged_count = tagged_count + 1
        elif isinstance(smartfolders, list) and len(smartfolders) > 0:
            tagged_count = tagged_count + 1
        portfolio_flag = a.get("bd.addedtoportfolio")
        if portfolio_flag:
            portfolio_count = portfolio_count + 1

    if total_assets == 0:
        is_enabled = False
        pct = 0.0
    else:
        pct = (tagged_count / total_assets) * 100.0
        is_enabled = tagged_count > 0

    input_summary = {
        "totalAssetsInSample": total_assets,
        "totalReportedByVendor": total_reported,
        "taggedViaSmartfolders": tagged_count,
        "addedToPortfolioCount": portfolio_count,
        "taggedPercentage": round(pct, 2),
    }

    if is_enabled:
        pass_reasons = [
            f"{tagged_count} of {total_assets} inventory assets ({round(pct, 2)}%) carry a non-empty bd.smartfolders value, indicating discovered assets are actively being classified into smart folders (the mechanism used to differentiate sanctioned vs. shadow-IT-discovered assets) rather than left undifferentiated."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"0 of {total_assets} sampled inventory assets (field census over all {total_reported} assets confirms bd.smartfolders is present on every record but populated on 0% of them) carry any bd.smartfolders tag value, meaning discovered assets -- including any shadow IT / unsanctioned business-unit-provisioned systems -- are not being explicitly tagged or differentiated from the rest of the inventory."
        ]
        recommendations = [
            "Configure Smart Folders (or an equivalent tagging mechanism) in Tenable ASM and assign discovered assets to them so that shadow IT / unsanctioned assets can be explicitly distinguished from sanctioned, portfolio-managed assets."
        ]

    result = {
        "isShadowITAssetTaggingEnabled": is_enabled,
        "totalAssets": total_assets,
        "taggedAssetsCount": tagged_count,
        "taggedAssetsPercentage": round(pct, 2),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isShadowITAssetTaggingEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
