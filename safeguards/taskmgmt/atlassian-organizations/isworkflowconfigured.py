import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Atlassian Organizations

    Checks: Whether organization policies are configured
    API Source: https://api.atlassian.com/admin/v2/orgs/{orgId}/policies
    Pass Condition: At least one policy exists in the organization

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "policyCount": int}
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
        policies = data.get("data", data.get("results", data.get("policies", [])))

        if isinstance(policies, list):
            result = len(policies) >= 1
            policy_count = len(policies)
        else:
            result = bool(data)
            policy_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "policyCount": policy_count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
