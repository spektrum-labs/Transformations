import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Dynatrace

    Checks: Whether Dynatrace problem detection is active and returning results
    API Source: https://{env-id}.live.dynatrace.com/api/v2/problems
    Pass Condition: API returns a valid problems response (problem detection is active)

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
        error = data.get("error", None)
        problems = data.get("problems", data.get("data", None))
        total_count = data.get("totalCount", 0)

        result = error is None and problems is not None
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "activeAlerts": total_count,
            "totalAlerts": total_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
