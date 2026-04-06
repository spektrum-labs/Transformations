import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Bitbucket (Git Code Repository)

    Checks: Whether Bitbucket Pipelines configuration is enabled with secure variable support
    API Source: GET https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/pipelines_config
    Pass Condition: Pipelines config exists and is enabled, indicating secure variables are available

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean}
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

        # Check if pipelines config is enabled (indicates secure variable support)
        enabled = data.get("enabled", False)
        if enabled:
            result = True
        elif data.get("type") == "pipeline_config":
            result = True
        elif data.get("repository") and data.get("enabled") is not None:
            result = bool(data.get("enabled"))
        # ── END EVALUATION LOGIC ──

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
