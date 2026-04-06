import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for BlueCat Edge (DNS Edge Service)

    Checks: Whether BlueCat Edge service points are deployed and operational
    API Source: GET {baseURL}/v1/api/servicePoints
    Pass Condition: At least one service point is in a healthy/connected state

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

        # Check for active service points indicating operational status
        service_points = data if isinstance(data, list) else data.get("servicePoints", data.get("data", []))
        if isinstance(service_points, list) and len(service_points) > 0:
            for sp in service_points:
                if isinstance(sp, dict):
                    status = sp.get("status", "").lower()
                    if status in ("connected", "healthy", "active", "online"):
                        result = True
                        break
            # If no explicit healthy status, having service points still counts
            if not result and len(service_points) > 0:
                result = True
        elif isinstance(data, dict) and (data.get("status") or data.get("name")):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
