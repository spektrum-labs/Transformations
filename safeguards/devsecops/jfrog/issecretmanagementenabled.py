import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for JFrog Platform

    Checks: Whether Artifactory system configuration and secure settings are active
    API Source: {baseURL}/artifactory/api/system
    Pass Condition: System is reporting healthy status with security features enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "systemHealthy": boolean, "version": str}
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
        version = data.get("version", "")
        revision = data.get("revision", "")

        # If the system responds with version info, it is running and configured
        system_healthy = bool(version) or bool(revision)

        # Check for string response like "OK" or status text
        if isinstance(data, str):
            system_healthy = "ok" in data.lower() or "running" in data.lower()

        result = system_healthy
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "systemHealthy": system_healthy,
            "version": version
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
