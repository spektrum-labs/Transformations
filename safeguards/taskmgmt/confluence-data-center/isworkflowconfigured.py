import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Confluence Data Center

    Checks: Whether spaces exist in Confluence Data Center
    API Source: {baseURL}/rest/api/space
    Pass Condition: At least one space exists

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
        results = data.get("results", data.get("data", []))

        if not isinstance(results, list):
            return {
                "isWorkflowConfigured": False,
                "spaceCount": 0,
                "error": "Unexpected spaces response format"
            }

        result = len(results) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "spaceCount": len(results)
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
