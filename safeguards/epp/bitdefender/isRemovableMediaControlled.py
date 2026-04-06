import json
import ast


def transform(input):
    """
    Evaluates isRemovableMediaControlled for Bitdefender GravityZone (EPP)

    Checks: Whether Device Control module is enabled in policies to restrict removable media
    API Source: POST /api/v1.0/jsonrpc/policies (method: getPoliciesList)
    Pass Condition: At least one policy has the Device Control module enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRemovableMediaControlled": boolean, ...metadata}
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False
        policies = data.get("result", data)
        if isinstance(policies, dict):
            policies = policies.get("items", policies.get("data", []))
        if not isinstance(policies, list):
            policies = []

        device_control_count = 0
        for p in policies:
            settings = p.get("settings", {})
            modules = settings.get("modules", {})
            device_control = modules.get("deviceControl", modules.get("device_control", {}))
            if isinstance(device_control, dict) and device_control.get("enabled", False):
                device_control_count += 1

        if device_control_count > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isRemovableMediaControlled": result,
            "deviceControlPolicies": device_control_count,
            "totalPolicies": len(policies)
        }

    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}
