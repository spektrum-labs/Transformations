import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for URLScan.

    Checks: Whether malicious verdict scan results are available
    API Source: GET https://urlscan.io/api/v1/search/?q=verdicts.overall.malicious:true
    Pass Condition: At least one scan with malicious verdict is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "alertCount": int}
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
        alerts = data.get("results", data.get("data", []))
        if not isinstance(alerts, list):
            alerts = []

        count = len(alerts)
        total = data.get("total", count)
        result = count >= 1 or (isinstance(total, int) and total > 0)
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "alertCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
