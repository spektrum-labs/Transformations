import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Cobalt.io (Pentest as a Service)

    Checks: Whether security policies or compliance configurations are defined
    API Source: GET https://api.us.cobalt.io/policies
    Pass Condition: At least one policy or compliance rule is configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean}
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
        result = False

        # Check for policies or compliance configurations
        policies = data.get("data", [])
        if isinstance(policies, list) and len(policies) > 0:
            for policy in policies:
                resource = policy.get("resource", policy)
                if isinstance(resource, dict) and (resource.get("id") or resource.get("name")):
                    result = True
                    break
        elif isinstance(policies, dict) and policies.get("resource"):
            result = True
        elif data.get("pagination", {}).get("total_count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
