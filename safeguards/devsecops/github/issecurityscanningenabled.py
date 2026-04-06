import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for GitHub (Code Hosting / DevOps)

    Checks: Whether code scanning alerts exist indicating active security scanning
    API Source: GET https://api.github.com/orgs/{org}/code-scanning/alerts
    Pass Condition: Code scanning is enabled (response is a list, even if empty alerts exist the feature is active)

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

        # -- EVALUATION LOGIC --
        result = False

        # A valid response (list of alerts) means code scanning is enabled
        if isinstance(data, list):
            result = True
        elif isinstance(data, dict):
            alerts = data.get("data", data.get("alerts", []))
            if isinstance(alerts, list):
                result = True
            elif data.get("total_count", 0) > 0:
                result = True
            elif data.get("message") and "no analysis found" not in str(data.get("message", "")).lower():
                result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
