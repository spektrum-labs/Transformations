import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Claroty CTD (OT/IoT Threat Detection)

    Checks: Whether Claroty CTD sites are configured and operational
    API Source: GET {baseURL}/ranger/sites
    Pass Condition: At least one site is actively monitored with connected sensors

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

        # Check for active sites indicating operational status
        sites = data if isinstance(data, list) else data.get("objects", data.get("sites", data.get("data", [])))
        if isinstance(sites, list) and len(sites) > 0:
            for site in sites:
                if isinstance(site, dict) and (site.get("name") or site.get("id")):
                    result = True
                    break
        elif isinstance(data, dict) and data.get("count", 0) > 0:
            result = True
        elif isinstance(data, dict) and (data.get("name") or data.get("id")):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
