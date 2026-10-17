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

    if not isinstance(assets, list):
        assets = []

    total_assets = len(assets)
    tagged_assets = 0
    sample_tags = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        smartfolders = asset.get("bd.smartfolders")
        if smartfolders is not None and isinstance(smartfolders, str) and smartfolders.strip() != "":
            tagged_assets = tagged_assets + 1
            if len(sample_tags) < 5:
                sample_tags.append(smartfolders)

    # Verdict is derived directly from the fraction of inventory assets
    # that carry a non-empty bd.smartfolders value in THIS response.
    is_enabled = total_assets > 0 and tagged_assets > 0

    input_summary = {
        "totalAssetsEvaluated": total_assets,
        "taggedAssetsCount": tagged_assets,
    }

    result = {
        "isShadowITAssetTaggingEnabled": is_enabled,
        "totalAssetsEvaluated": total_assets,
        "taggedAssetsCount": tagged_assets,
    }

    if total_assets == 0:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No inventory assets were returned by listInventoryAssets, so smart-folder/tag "
                          "based shadow IT classification cannot be confirmed as active."],
            recommendations=["Verify the ASM inventory endpoint returns assets and configure smart folders "
                              "to tag unsanctioned/shadow IT assets."],
            input_summary=input_summary,
            metadata={"transformationId": "isShadowITAssetTaggingEnabled",
                      "vendor": "Tenable Attack Surface Management", "category": "asm"},
        )

    if is_enabled:
        pass_reasons = [
            f"{tagged_assets} of {total_assets} inventory assets (bd.smartfolders field) carry a non-empty "
            f"smart-folder/tag value, e.g. {sample_tags}. This confirms assets are being explicitly tagged "
            f"and are not blended undifferentiated into the general inventory."
        ]
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary=input_summary,
            metadata={"transformationId": "isShadowITAssetTaggingEnabled",
                      "vendor": "Tenable Attack Surface Management", "category": "asm"},
        )
    else:
        fail_reasons = [
            f"None of the {total_assets} inventory assets returned by listInventoryAssets carry a non-empty "
            f"bd.smartfolders value (0 tagged out of {total_assets} sampled). Smart-folder/tag-based "
            f"classification used to flag shadow IT assets does not appear to be configured or applied."
        ]
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=["Create smart folders / portfolio tags in Tenable ASM and apply them to assets "
                              "identified as unsanctioned or business-unit-provisioned (shadow IT) so they are "
                              "explicitly distinguishable from sanctioned inventory."],
            input_summary=input_summary,
            metadata={"transformationId": "isShadowITAssetTaggingEnabled",
                      "vendor": "Tenable Attack Surface Management", "category": "asm"},
        )
