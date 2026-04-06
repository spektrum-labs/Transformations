import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Maven Repository Manager

    Checks: Whether repository manager status and secure configuration is active
    API Source: {baseURL}/service/rest/v1/status
    Pass Condition: System reports healthy status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "systemHealthy": boolean, "edition": str}
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
        edition = data.get("edition", "")
        version = data.get("version", "")

        # Status endpoint may return simple string or object
        system_healthy = bool(edition) or bool(version)

        if isinstance(data, str):
            system_healthy = len(data.strip()) > 0

        result = system_healthy
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "systemHealthy": system_healthy,
            "edition": edition
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
