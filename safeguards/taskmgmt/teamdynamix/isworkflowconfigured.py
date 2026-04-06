import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for TeamDynamix

    Checks: Whether ticket types are configured in TeamDynamix
    API Source: https://{instance}.teamdynamix.com/TDWebApi/api/{appId}/tickets/types
    Pass Condition: At least 1 ticket type exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "typeCount": int}
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
        types = data if isinstance(data, list) else data.get("data", data.get("types", []))

        if not isinstance(types, list):
            types = [types] if isinstance(types, dict) else []

        count = len(types)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "typeCount": count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
