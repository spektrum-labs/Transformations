import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Thinkst Canary

    Checks: Whether unacknowledged canary alerts are being generated and reported
    API Source: /api/v1/incidents/unacknowledged
    Pass Condition: API responds successfully indicating alert monitoring is active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "unacknowledgedCount": int}
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
        has_error = data.get("error") is not None
        incidents = data.get("incidents", data.get("data", []))
        if not isinstance(incidents, list):
            incidents = []

        count = len(incidents)
        result = isinstance(data, dict) and not has_error
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "unacknowledgedCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
