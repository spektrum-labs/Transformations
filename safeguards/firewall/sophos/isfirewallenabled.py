# isfirewallenabled.py - Sophos Firewall Management API
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"]
    data = input_data
    if isinstance(data, dict):
        for key in ["response", "result", "apiResponse", "Output"]:
            if key in data and isinstance(data.get(key), dict):
                data = data[key]
    return data


def create_response(result, pass_reasons=None, fail_reasons=None, input_summary=None, transformation_errors=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": []},
            "transformation": {"status": "error" if transformation_errors else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "transformationId": "isFirewallEnabled", "vendor": "Sophos", "category": "Firewall"}
        }
    }


def transform(input):
    criteriaKey = "isFirewallEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data = extract_input(input)
        items = data.get("items", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = []

        total = len(items)
        connected = 0
        for fw in items:
            if not isinstance(fw, dict):
                continue
            status = fw.get("status", {})
            if isinstance(status, dict) and status.get("connected") is True:
                connected += 1

        is_enabled = total > 0 and connected > 0

        pass_reasons, fail_reasons = [], []
        if is_enabled:
            pass_reasons.append(f"{connected} of {total} Sophos firewall device(s) connected via /firewall/v1/firewalls")
        else:
            fail_reasons.append("No connected Sophos firewall devices found")

        return create_response(
            result={criteriaKey: is_enabled, "totalFirewalls": total, "connectedFirewalls": connected},
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            input_summary={"totalFirewalls": total, "connectedFirewalls": connected}
        )
    except Exception as e:
        return create_response(result={criteriaKey: False}, transformation_errors=[str(e)])
