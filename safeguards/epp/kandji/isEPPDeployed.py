import json
import ast


def transform(input):
    """
    Evaluates isEPPDeployed for Kandji (EPP)

    Checks: Whether Kandji agent is deployed and managing Apple endpoints
    API Source: GET /api/v1/devices
    Pass Condition: Managed devices exist in the Kandji tenant

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isEPPDeployed": boolean, ...metadata}
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
        devices = data if isinstance(data, list) else data.get("results", data.get("devices", data.get("data", [])))
        if not isinstance(devices, list):
            devices = []

        total = len(devices)
        enrolled = 0
        for d in devices:
            blueprint = d.get("blueprint_id", d.get("blueprintId", ""))
            mdm_enabled = d.get("mdm_enabled", d.get("mdmEnabled", False))
            if blueprint or mdm_enabled:
                enrolled += 1

        if total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPDeployed": result,
            "totalDevices": total,
            "enrolledDevices": enrolled
        }

    except Exception as e:
        return {"isEPPDeployed": False, "error": str(e)}
