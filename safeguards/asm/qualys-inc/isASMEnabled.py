"""
Transformation: isASMEnabled
Vendor: Qualys, Inc.  |  Category: asm
Evaluates: Whether the Qualys External Attack Surface Management (EASM) module is enabled,
determined by a successful response containing EASM-tagged assets from the asset search endpoint.
"""
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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isASMEnabled", "vendor": "Qualys, Inc.", "category": "asm"}
        }
    }


def evaluate(data):
    """
    Checks the Qualys EASM asset search API response.
    returnSpec: { assetList: list, responseCode: str, count: int }
    A valid response with EASM-tagged assets (assetList non-empty or count > 0) confirms
    the ASM module is enabled and actively discovering internet-facing assets.
    """
    try:
        if not isinstance(data, dict):
            return {"isASMEnabled": False, "error": "Unexpected response format: data is not a dict"}

        response_code = data.get("responseCode", "")
        response_code_str = str(response_code) if response_code is not None else ""

        asset_list = data.get("assetList", [])
        if not isinstance(asset_list, list):
            asset_list = []

        count = data.get("count", None)
        asset_count = 0
        if count is not None:
            try:
                asset_count = int(count)
            except Exception:
                asset_count = len(asset_list)
        else:
            asset_count = len(asset_list)

        asm_enabled = asset_count > 0 or len(asset_list) > 0

        sample_assets = []
        shown = 0
        for asset in asset_list:
            if shown >= 5:
                break
            if isinstance(asset, dict):
                asset_id = asset.get("id", "")
                asset_name = asset.get("name", "")
                if asset_id or asset_name:
                    sample_assets.append(str(asset_id) + " - " + str(asset_name))
            shown = shown + 1

        return {
            "isASMEnabled": asm_enabled,
            "responseCode": response_code_str,
            "easmAssetCount": asset_count,
            "sampleAssets": sample_assets
        }
    except Exception as e:
        return {"isASMEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isASMEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("EASM asset search endpoint returned EASM-tagged assets")
            pass_reasons.append("Qualys ASM module is enabled and discovering internet-facing assets")
            pass_reasons.append("EASM asset count: " + str(extra_fields.get("easmAssetCount", 0)))
            sample = extra_fields.get("sampleAssets", [])
            if sample:
                additional_findings.append("Sample EASM assets discovered: " + ", ".join(sample))
        else:
            fail_reasons.append("EASM asset search returned no EASM-tagged assets")
            fail_reasons.append("Qualys ASM module may not be enabled or no internet-facing assets are tagged")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            recommendations.append("Verify the CSAM-EASM toggle is enabled in your Qualys Cloud Platform Inventory tab")
            recommendations.append("Ensure internet-facing assets are tagged with the 'EASM' tag in Qualys")
            recommendations.append("Contact your Qualys account manager to enable the EASM module")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "easmAssetCount": extra_fields.get("easmAssetCount", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
