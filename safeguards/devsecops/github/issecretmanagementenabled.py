import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for GitHub (Code Hosting / DevOps)

    Checks: Whether secret scanning is enabled and alerts are being tracked
    API Source: GET https://api.github.com/orgs/{org}/secret-scanning/alerts
    Pass Condition: Secret scanning is enabled (response is a list, indicating the feature is active)

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

        # A valid response (list of alerts) means secret scanning is enabled
        if isinstance(data, list):
            result = True
        elif isinstance(data, dict):
            alerts = data.get("data", data.get("alerts", []))
            if isinstance(alerts, list):
                result = True
            elif data.get("total_count", 0) > 0:
                result = True
            elif data.get("enabled") or data.get("secret_scanning", {}).get("status") == "enabled":
                result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
