import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Bitbucket (Git Code Repository)

    Checks: Whether Bitbucket Pipelines are configured and running for the repository
    API Source: GET https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/pipelines
    Pass Condition: At least one pipeline execution exists indicating CI/CD scanning is active

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

        # ── EVALUATION LOGIC ──
        result = False

        # Check for pipeline executions indicating scanning is enabled
        pipelines = data.get("values", [])
        if isinstance(pipelines, list) and len(pipelines) > 0:
            result = True
        elif data.get("size", 0) > 0:
            result = True
        elif data.get("pagelen", 0) > 0 and data.get("values") is not None:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
