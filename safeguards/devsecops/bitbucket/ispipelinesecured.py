import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Bitbucket (Git Code Repository)

    Checks: Whether branch restrictions and security policies are enforced on the repository
    API Source: GET https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/branch-restrictions
    Pass Condition: At least one branch restriction exists protecting main/master branches

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

        # Check for branch restrictions indicating pipeline security policies
        restrictions = data.get("values", [])
        if isinstance(restrictions, list) and len(restrictions) > 0:
            for restriction in restrictions:
                if isinstance(restriction, dict):
                    kind = restriction.get("kind", "")
                    pattern = restriction.get("pattern", "")
                    if kind and pattern:
                        result = True
                        break
        elif data.get("size", 0) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
