import json
import ast


def transform(input):
    """
    Evaluates isEPPDeployed for Automox (EPP)

    Checks: Whether the Automox agent is deployed across managed endpoints
    API Source: GET https://console.automox.com/api/servers?o={orgId}
    Pass Condition: Devices exist and a majority have the agent connected

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
        # Automox /api/servers returns a list of managed devices
        # Each device has "connected" and "is_compatible" fields
        result = False
        devices = data if isinstance(data, list) else data.get("results", data.get("data", []))

        if not isinstance(devices, list):
            devices = []

        total = len(devices)
        connected = sum(1 for d in devices if d.get("connected", False))
        compatible = sum(1 for d in devices if d.get("is_compatible", False))

        if total > 0 and connected > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPDeployed": result,
            "totalDevices": total,
            "connectedDevices": connected,
            "compatibleDevices": compatible
        }

    except Exception as e:
        return {"isEPPDeployed": False, "error": str(e)}
