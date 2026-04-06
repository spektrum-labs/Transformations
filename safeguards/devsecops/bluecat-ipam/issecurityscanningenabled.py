import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for BlueCat IPAM (IP Address Management)

    Checks: Whether IP ranges are configured and being managed
    API Source: GET {baseURL}/api/v2/ipRanges
    Pass Condition: At least one IP range exists indicating active IP address scanning

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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

        # Check for IP ranges indicating active scanning
        ranges = data if isinstance(data, list) else data.get("data", data.get("ipRanges", []))
        if isinstance(ranges, list) and len(ranges) > 0:
            result = True
        elif isinstance(data, dict) and data.get("count", 0) > 0:
            result = True
        elif isinstance(data, dict) and (data.get("id") or data.get("range")):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
