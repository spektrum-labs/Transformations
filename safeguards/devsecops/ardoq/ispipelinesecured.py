import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Ardoq

    Checks: Whether workspaces are configured for architecture governance
    API Source: {baseURL}/api/v2/workspaces
    Pass Condition: At least one workspace is configured and accessible

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "activeWorkspaces": int, "totalWorkspaces": int}
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
        workspaces = data.get("values", data.get("data", data.get("workspaces", data.get("items", []))))

        if not isinstance(workspaces, list):
            total_count = data.get("totalCount", data.get("total", data.get("count", 0)))
            if isinstance(total_count, int) and total_count > 0:
                return {
                    "isPipelineSecured": True,
                    "activeWorkspaces": total_count,
                    "totalWorkspaces": total_count
                }
            return {
                "isPipelineSecured": False,
                "activeWorkspaces": 0,
                "totalWorkspaces": 0,
                "error": "Unexpected response format"
            }

        total = len(workspaces)
        active = []
        for ws in workspaces:
            comp_count = ws.get("componentCount", ws.get("component_count", -1))
            if comp_count > 0:
                active.append(ws)
            elif comp_count == -1:
                active.append(ws)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "activeWorkspaces": len(active),
            "totalWorkspaces": total
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
