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
        stats = {}
    elif isinstance(data, dict):
        assets = data.get("assets") or []
        total = data.get("total")
        if total is None:
            total = len(assets)
        stats = data.get("stats") or {}
    else:
        assets = []
        total = 0
        stats = {}

    stats_total = stats.get("total") if isinstance(stats, dict) else None
    is_enabled = bool(total and total > 0) or bool(len(assets) > 0)

    input_summary = {
        "totalAssetsReported": total,
        "assetsInResponse": len(assets),
        "statsTotal": stats_total,
        "hostcount": stats.get("hostcount") if isinstance(stats, dict) else None,
    }

    if is_enabled:
        pass_reasons = [
            f"Inventory endpoint returned a populated asset list (total={total}, "
            f"{len(assets)} assets in response, stats.total={stats_total}), "
            f"indicating the ASM module is provisioned and actively discovering assets for this tenant."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Inventory endpoint returned no assets (total={total}, "
            f"{len(assets)} assets in response), indicating the ASM module is not "
            f"provisioned or not reachable for this tenant."
        ]
        recommendations = [
            "Verify the ASM container/license is provisioned and that the API token has access to the inventory endpoint."
        ]

    result = {
        "isASMEnabled": is_enabled,
        "totalAssets": total,
        "assetsInResponse": len(assets),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isASMEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
