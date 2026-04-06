import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for ClickUp

    Checks: Whether spaces exist in the ClickUp workspace
    API Source: https://api.clickup.com/api/v2/team/{teamId}/space
    Pass Condition: At least one space exists in the workspace

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "spaceCount": int}
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
        spaces = data.get("spaces", data.get("data", []))

        if not isinstance(spaces, list):
            return {
                "isWorkflowConfigured": False,
                "spaceCount": 0,
                "error": "Unexpected spaces response format"
            }

        result = len(spaces) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "spaceCount": len(spaces)
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
