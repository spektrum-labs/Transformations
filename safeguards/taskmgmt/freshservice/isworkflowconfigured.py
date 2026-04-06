import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Freshservice (IT Service Management)

    Checks: Whether automation rules are defined in Freshservice
    API Source: https://{domain}.freshservice.com/api/v2/automations
    Pass Condition: At least 1 automation rule is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "workflowCount": int}
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
        automations = data.get("automations", data.get("rules", data.get("results", [])))

        if not isinstance(automations, list):
            return {
                "isWorkflowConfigured": False,
                "workflowCount": 0,
                "error": "Unexpected response format"
            }

        workflow_count = len(automations)
        result = workflow_count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "workflowCount": workflow_count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
