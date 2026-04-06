import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for PagerDuty

    Checks: Whether at least one service is configured in PagerDuty
    API Source: https://api.pagerduty.com/services
    Pass Condition: At least 1 service exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "serviceCount": int}
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
        services = data.get("services", data.get("data", []))

        if not isinstance(services, list):
            return {
                "isWorkflowConfigured": False,
                "serviceCount": 0,
                "error": "Unexpected services response format"
            }

        count = len(services)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "serviceCount": count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
