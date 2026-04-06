import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Claroty CTD (OT/IoT Threat Detection)

    Checks: Whether the Claroty CTD instance is accessible and has active sites
    API Source: GET {baseURL}/ranger/sites
    Pass Condition: API returns valid site data confirming active CTD deployment

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # Check for valid site data confirming active CTD license
        if isinstance(data, list) and len(data) > 0:
            result = True
        elif isinstance(data, dict):
            sites = data.get("sites", data.get("data", data.get("objects", [])))
            if isinstance(sites, list) and len(sites) > 0:
                result = True
            elif data.get("id") or data.get("name") or data.get("site_id"):
                result = True
            elif data.get("count", 0) > 0:
                result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
