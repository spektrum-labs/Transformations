import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for BlueCat Edge (DNS Edge Service)

    Checks: Whether DNS domain lists are configured for threat monitoring
    API Source: GET {baseURL}/v1/api/list/dns
    Pass Condition: At least one DNS domain list exists for security filtering

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

        # Check for DNS domain lists indicating security scanning
        lists = data if isinstance(data, list) else data.get("domainLists", data.get("data", []))
        if isinstance(lists, list) and len(lists) > 0:
            result = True
        elif isinstance(data, dict) and (data.get("id") or data.get("name")):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
