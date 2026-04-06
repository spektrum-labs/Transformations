import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for YesWeHack (European Bug Bounty Platform)

    Checks: Whether vulnerability reports exist from bug bounty scanning
    API Source: GET https://api.yeswehack.com/reports
    Pass Condition: At least one vulnerability report exists

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

        # Check for vulnerability reports from bug bounty programs
        items = data.get("items", data.get("data", data.get("reports", [])))
        if isinstance(items, list) and len(items) > 0:
            result = True
        elif data.get("total", data.get("nb_results", 0)) > 0:
            result = True
        elif data.get("pagination", {}).get("nb_results", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
