import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for SolarWinds Service Desk

    Checks: Whether categories are configured in SolarWinds Service Desk
    API Source: https://api.samanage.com/categories.json
    Pass Condition: At least 1 category exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "categoryCount": int}
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
        categories = data if isinstance(data, list) else data.get("data", data.get("categories", []))

        if not isinstance(categories, list):
            return {
                "isWorkflowConfigured": False,
                "categoryCount": 0,
                "error": "Unexpected categories response format"
            }

        count = len(categories)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "categoryCount": count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
