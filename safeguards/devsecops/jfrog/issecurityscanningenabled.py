import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for JFrog Platform

    Checks: Whether JFrog Xray security scanning is configured and active
    API Source: {baseURL}/xray/api/v1/scanArtifact
    Pass Condition: Xray scan results or scan configuration is present

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "scanCount": int, "xrayActive": boolean}
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
        artifacts = data.get("artifacts", data.get("data", data.get("results", [])))
        xray_active = bool(data.get("info", data.get("status", "")))

        if isinstance(artifacts, list):
            scan_count = len(artifacts)
        else:
            scan_count = 1 if artifacts else 0

        result = scan_count > 0 or xray_active
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "scanCount": scan_count,
            "xrayActive": xray_active
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
