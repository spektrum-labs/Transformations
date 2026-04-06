import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Atlassian Crowd

    Checks: Whether group memberships are queryable in Crowd
    API Source: {baseURL}/rest/usermanagement/latest/group/membership
    Pass Condition: A valid group membership response is returned

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
        memberships = data.get("memberships", data.get("groups", data.get("data", [])))

        if isinstance(memberships, list):
            result = len(memberships) >= 1
            group_count = len(memberships)
        else:
            result = bool(data)
            group_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "groupCount": group_count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
