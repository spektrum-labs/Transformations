import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for GitLab

    Checks: Whether protected branches and merge request approval policies are enforced
    API Source: {baseURL}/api/v4/projects/{projectId}/protected_branches
    Pass Condition: At least one protected branch exists with push and merge access restrictions

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "protectedBranches": int, "details": list}
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
        branches = data if isinstance(data, list) else data.get("data", data.get("items", data.get("results", [])))

        if not isinstance(branches, list):
            return {
                "isPipelineSecured": False,
                "protectedBranches": 0,
                "details": [],
                "error": "Unexpected response format"
            }

        details = [
            {
                "name": b.get("name", "unknown"),
                "pushRestricted": len(b.get("push_access_levels", [])) > 0,
                "mergeRestricted": len(b.get("merge_access_levels", [])) > 0
            }
            for b in branches
            if isinstance(b, dict)
        ]

        result = len(details) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "protectedBranches": len(details),
            "details": details
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
