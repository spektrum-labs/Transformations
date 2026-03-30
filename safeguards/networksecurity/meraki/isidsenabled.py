"""
Transformation: isIDSEnabled
Vendor: Cisco Meraki  |  Category: Network Security
Evaluates: Whether IDS is enabled (detection or prevention mode)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isIDSEnabled", "vendor": "Cisco Meraki", "category": "Network Security"}
        }
    }


def evaluate(data):
    """Check IDS is enabled across appliance networks (detection/prevention) and wireless (Air Marshal block)."""
    try:
        intrusion_list = data.get('intrusionSettings', [])
        if isinstance(intrusion_list, dict):
            intrusion_list = [intrusion_list]

        air_marshal = data.get('airMarshalSettings', {})
        am_items = air_marshal.get('items', []) if isinstance(air_marshal, dict) else []

        if not intrusion_list and not am_items:
            mode = data.get('mode', 'disabled')
            return {"isIDSEnabled": mode in ['detection', 'prevention'], "currentMode": mode}

        appliance_without_ids = []
        for entry in intrusion_list:
            mode = entry.get('mode', 'disabled')
            if mode not in ['detection', 'prevention']:
                appliance_without_ids.append(entry.get('networkId', 'unknown'))

        wireless_without_ids = []
        for item in am_items:
            if item.get('defaultPolicy') == 'allow':
                wireless_without_ids.append(item.get('networkId', 'unknown'))

        all_enabled = len(appliance_without_ids) == 0 and len(wireless_without_ids) == 0
        has_any = len(intrusion_list) > 0 or len(am_items) > 0

        return {
            "isIDSEnabled": all_enabled and has_any,
            "applianceNetworksEvaluated": len(intrusion_list),
            "wirelessNetworksEvaluated": len(am_items),
            "applianceWithoutIDS": appliance_without_ids,
            "wirelessWithoutIDS": wireless_without_ids
        }
    except Exception as e:
        return {"isIDSEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isIDSEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Cisco Meraki configuration for {criteriaKey}")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
