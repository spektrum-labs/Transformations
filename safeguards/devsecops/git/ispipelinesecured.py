import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Git (Generic Git Provider)

    Checks: Whether branch protection rules are configured on the repository
    API Source: GET {baseURL}/projects/{projectId}/protected_branches
    Pass Condition: At least one protected branch rule exists

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

        # Check for protected branch rules indicating pipeline security
        branches = data if isinstance(data, list) else data.get("data", data.get("values", []))
        if isinstance(branches, list) and len(branches) > 0:
            for branch in branches:
                if isinstance(branch, dict) and (branch.get("id") or branch.get("name")):
                    result = True
                    break
        elif isinstance(branches, dict) and branches.get("id"):
            result = True
        elif data.get("total", data.get("size", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
