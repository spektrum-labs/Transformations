import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Burp Suite DAST (Dynamic Application Security Testing)

    Checks: Whether DAST scans have been executed on the instance
    API Source: GET {baseURL}/api/scans
    Pass Condition: At least one scan exists indicating active security scanning

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

        # Check for scan entries indicating DAST scanning is enabled
        scans = data.get("scans", data.get("data", []))
        if isinstance(scans, list) and len(scans) > 0:
            result = True
        elif data.get("total_count", 0) > 0:
            result = True
        elif data.get("scan_count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
