import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for Asana

    Checks: Whether projects exist in the Asana workspace
    API Source: https://app.asana.com/api/1.0/projects?workspace={workspaceGid}
    Pass Condition: At least one project exists in the workspace

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "projectCount": int}
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
        projects = data.get("data", [])

        if not isinstance(projects, list):
            return {
                "isWorkflowConfigured": False,
                "projectCount": 0,
                "error": "Unexpected projects response format"
            }

        result = len(projects) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "projectCount": len(projects)
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
