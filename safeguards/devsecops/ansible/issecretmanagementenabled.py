import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Ansible Automation Platform

    Checks: Whether the Ansible controller is operational and responding
    API Source: {baseURL}/api/v2/ping/
    Pass Condition: Ping endpoint returns a valid response with active instances

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "activeInstances": int}
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
        instances = data.get("instances", data.get("data", data.get("results", [])))

        if isinstance(instances, list):
            active = len(instances)
            result = active > 0
        elif isinstance(instances, dict):
            active = instances.get("count", instances.get("total", 0))
            result = active > 0
        else:
            ha = data.get("ha", False)
            version = data.get("version", "")
            active = 1 if version else 0
            result = bool(version)
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "activeInstances": active
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
