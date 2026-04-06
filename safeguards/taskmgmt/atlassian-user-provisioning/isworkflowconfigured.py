import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Atlassian User Provisioning (SCIM)

    Checks: Whether SCIM groups exist in the provisioning directory
    API Source: https://api.atlassian.com/scim/directory/{directoryId}/Groups
    Pass Condition: At least one SCIM group exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "groupCount": int}
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
        total_results = data.get("totalResults", 0)
        resources = data.get("Resources", data.get("resources", []))

        if isinstance(resources, list):
            result = len(resources) >= 1
            group_count = len(resources) if resources else total_results
        else:
            result = total_results >= 1
            group_count = total_results
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "groupCount": group_count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
