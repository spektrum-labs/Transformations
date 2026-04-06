import json
import ast


def transform(input):
    """
    Evaluates isEDRDeployed for Automox (EPP)

    Checks: Whether Automox agents are deployed and actively reporting on endpoints
    API Source: GET https://console.automox.com/api/servers?o={orgId}
    Pass Condition: At least one device is connected and reporting with the Automox agent

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
        # Automox /api/servers returns a list of devices with connected status
        # Each device has "connected" (bool) and "is_compatible" fields
        result = False
        devices = data if isinstance(data, list) else data.get("results", data.get("data", []))

        if not isinstance(devices, list):
            devices = []

        total = len(devices)
        connected = sum(1 for d in devices if d.get("connected", False))

        if total > 0 and connected > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEDRDeployed": result,
            "totalDevices": total,
            "connectedDevices": connected
        }

    except Exception as e:
        return {"isEDRDeployed": False, "error": str(e)}
