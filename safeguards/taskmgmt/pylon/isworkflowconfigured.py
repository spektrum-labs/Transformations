import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Pylon

    Checks: Whether ticket forms are configured in Pylon
    API Source: https://api.usepylon.com/ticket-forms
    Pass Condition: At least 1 ticket form exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "formCount": int}
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
        forms = data.get("data", data.get("ticket_forms", data.get("results", [])))

        if not isinstance(forms, list):
            return {
                "isWorkflowConfigured": False,
                "formCount": 0,
                "error": "Unexpected ticket forms response format"
            }

        count = len(forms)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "formCount": count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
