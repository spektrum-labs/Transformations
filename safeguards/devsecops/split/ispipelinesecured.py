import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Split (Feature Flag / Experimentation Platform)

    Checks: Whether access control groups are configured
    API Source: GET https://api.split.io/internal/api/v2/groups
    Pass Condition: At least one group exists enforcing access policies

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

        # Check for access control groups
        objects = data.get("objects", data.get("data", data.get("groups", [])))
        if isinstance(objects, list) and len(objects) > 0:
            for group in objects:
                if isinstance(group, dict):
                    name = group.get("name", group.get("id", ""))
                    if name:
                        result = True
                        break
        elif data.get("totalCount", data.get("total", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
