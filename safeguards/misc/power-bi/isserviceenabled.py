import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Power BI

    Checks: Whether workspaces are retrievable from Power BI
    API Source: https://api.powerbi.com/v1.0/myorg/groups
    Pass Condition: The API returns a workspaces array

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean, "workspaceCount": int}
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
        workspaces = data.get("value", data.get("workspaces", []))
        if isinstance(workspaces, list):
            result = True
            workspace_count = len(workspaces)
        else:
            result = bool(data) and "error" not in data
            workspace_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "workspaceCount": workspace_count
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
