import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Akamai Identity Cloud Social

    Checks: Whether social login clients are configured and active
    API Source: {baseURL}/config/{appId}/clients
    Pass Condition: At least one API client is configured for the application

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "activeClients": int, "totalClients": int}
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

        # -- EVALUATION LOGIC --
        clients = data.get("data", data.get("clients", data.get("results", data.get("items", []))))

        if not isinstance(clients, list):
            return {
                "isSecurityScanningEnabled": False,
                "activeClients": 0,
                "totalClients": 0,
                "error": "Unexpected response format"
            }

        total = len(clients)
        active = []
        for client in clients:
            enabled = client.get("enabled", client.get("active", client.get("status", "")))
            if enabled is True:
                active.append(client)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(client)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "activeClients": len(active),
            "totalClients": total
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
