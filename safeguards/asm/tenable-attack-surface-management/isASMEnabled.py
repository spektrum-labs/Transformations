"""Transformation: isASMEnabled"""
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
        if not isinstance(assets, list):
            assets = []
        total_val = data.get("total")
        total = total_val if isinstance(total_val, int) else len(assets)
        stats = data.get("stats") or {}
        if not isinstance(stats, dict):
            stats = {}
    else:
        assets = []
        total = 0
        stats = {}

    is_enabled = total > 0 or len(assets) > 0

    input_summary = {
        "totalAssetsReported": total,
        "assetsInResponse": len(assets),
        "statsTotal": stats.get("total"),
        "hostcount": stats.get("hostcount"),
        "domaincount": stats.get("domaincount"),
        "ipcount": stats.get("ipcount"),
    }

    if is_enabled:
        pass_reasons = [
            f"ASM inventory endpoint returned {total} total assets ({len(assets)} in this page), "
            f"with stats.total={stats.get('total')}, hostcount={stats.get('hostcount')}, "
            f"ipcount={stats.get('ipcount')} — the ASM discovery module is actively provisioned "
            f"and returning data for this tenant."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "ASM inventory endpoint returned zero assets (total=0, no records in 'assets' list), "
            "indicating the Attack Surface Management module is not provisioned or not reachable "
            "for this tenant."
        ]
        recommendations = [
            "Verify the Tenable ASM module is licensed and provisioned for this tenant, and that "
            "at least one discovery source has been configured to populate the inventory."
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
