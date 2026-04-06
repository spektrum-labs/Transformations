import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for BMC Remedy

    Checks: Whether change management records exist in BMC Remedy
    API Source: {baseURL}/api/arsys/v1/entry/CHG:Infrastructure Change
    Pass Condition: At least one change record exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "changeCount": int}
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
        entries = data.get("entries", data.get("data", data.get("results", [])))

        if isinstance(entries, list):
            result = len(entries) >= 1
            change_count = len(entries)
        else:
            result = bool(data)
            change_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "changeCount": change_count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
