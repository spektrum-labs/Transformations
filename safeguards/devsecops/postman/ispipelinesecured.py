import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Postman (API Development Platform)

    Checks: Whether workspaces are configured with governance policies
    API Source: GET https://api.getpostman.com/workspaces
    Pass Condition: At least one workspace exists with proper configuration

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

        # Check for workspaces with governance configuration
        workspaces = data.get("workspaces", [])
        if isinstance(workspaces, list) and len(workspaces) > 0:
            for workspace in workspaces:
                if isinstance(workspace, dict):
                    ws_type = workspace.get("type", "")
                    ws_name = workspace.get("name", "")
                    if ws_type or ws_name:
                        result = True
                        break
        elif data.get("total", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
