import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for ANY.RUN.

    Checks: Whether malicious analysis results are available as alerts
    API Source: GET https://api.any.run/v1/analysis?verdict=malicious
    Pass Condition: At least one malicious verdict analysis exists

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
        alerts = data.get("data", data.get("tasks", data.get("results", [])))
        if not isinstance(alerts, list):
            alerts = []

        count = len(alerts)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "alertCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
