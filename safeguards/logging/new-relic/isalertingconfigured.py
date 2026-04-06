import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for New Relic

    Checks: Whether at least one alert policy is configured
    API Source: https://api.newrelic.com/v2/alerts_policies.json
    Pass Condition: At least one alert policy exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "activeAlerts": int, "totalAlerts": int}
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
        policies = data.get("policies", data.get("data", data.get("items", [])))

        if not isinstance(policies, list):
            policies = [policies] if policies else []

        total = len(policies)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "activeAlerts": total,
            "totalAlerts": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
