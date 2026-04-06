import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for BlueCat IPAM (IP Address Management)

    Checks: Whether BlueCat Address Manager configurations are deployed and operational
    API Source: GET {baseURL}/api/v2/configurations
    Pass Condition: At least one configuration exists indicating the system is operational

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean}
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

        # Check for configurations indicating operational status
        configs = data if isinstance(data, list) else data.get("data", data.get("configurations", []))
        if isinstance(configs, list) and len(configs) > 0:
            result = True
        elif isinstance(data, dict) and data.get("count", 0) > 0:
            result = True
        elif isinstance(data, dict) and (data.get("id") or data.get("name")):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
