import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for BlueCat Edge (DNS Edge Service)

    Checks: Whether DNS security policies are configured and enforced
    API Source: GET {baseURL}/v1/api/policies
    Pass Condition: At least one DNS policy exists with active enforcement rules

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

        # ── EVALUATION LOGIC ──
        result = False

        # Check for DNS policies indicating pipeline security
        policies = data if isinstance(data, list) else data.get("policies", data.get("data", []))
        if isinstance(policies, list) and len(policies) > 0:
            for policy in policies:
                if isinstance(policy, dict) and (policy.get("name") or policy.get("id")):
                    result = True
                    break
        elif isinstance(data, dict) and data.get("id"):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
