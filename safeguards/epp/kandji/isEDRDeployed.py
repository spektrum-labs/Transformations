import json
import ast


def transform(input):
    """
    Evaluates isEDRDeployed for Kandji (EPP)

    Checks: Whether managed devices have threat detection capabilities
    API Source: GET /api/v1/devices
    Pass Condition: At least one device exists and is managed by Kandji

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isEDRDeployed": boolean, ...metadata}
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
        managed = 0
        for d in devices:
            mdm_enabled = d.get("mdm_enabled", d.get("mdmEnabled", False))
            agent_installed = d.get("agent_installed", d.get("agentInstalled", False))
            if mdm_enabled or agent_installed:
                managed += 1

        if total > 0 and managed > 0:
            result = True
        elif total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEDRDeployed": result,
            "totalDevices": total,
            "managedDevices": managed
        }

    except Exception as e:
        return {"isEDRDeployed": False, "error": str(e)}
