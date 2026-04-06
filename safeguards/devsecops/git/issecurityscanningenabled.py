import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Git (Generic Git Provider)

    Checks: Whether repositories or projects are accessible indicating active usage
    API Source: GET {baseURL}/projects
    Pass Condition: At least one project or repository exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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

        # Check for projects or repositories indicating active usage
        projects = data if isinstance(data, list) else data.get("data", data.get("projects", data.get("values", [])))
        if isinstance(projects, list) and len(projects) > 0:
            result = True
        elif isinstance(projects, dict) and projects.get("id"):
            result = True
        elif data.get("total", data.get("total_count", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
