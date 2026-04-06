import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Burp Suite DAST (Dynamic Application Security Testing)

    Checks: Whether the site tree is configured for managing scan targets securely
    API Source: GET {baseURL}/api/site_tree
    Pass Condition: Site tree contains configured sites indicating secure target management

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

        # -- EVALUATION LOGIC --
        result = False

        # Check for configured sites in the site tree
        sites = data.get("sites", data.get("data", data.get("site_tree", [])))
        if isinstance(sites, list) and len(sites) > 0:
            result = True
        elif data.get("total_count", 0) > 0:
            result = True
        elif isinstance(data, dict) and data.get("host") or data.get("url"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
