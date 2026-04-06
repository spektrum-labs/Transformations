import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for OneDrive (Microsoft Cloud Storage)

    Checks: Whether the OneDrive drive metadata and quota are accessible
    API Source: GET https://graph.microsoft.com/v1.0/users/{userId}/drive
    Pass Condition: API returns valid drive metadata including quota information

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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

        drive_id = data.get("driveId", data.get("id", ""))
        drive_type = data.get("driveType", "")
        quota = data.get("quota", {})
        owner = data.get("owner", "")

        if drive_id and drive_type:
            result = True
        elif drive_id and isinstance(quota, dict) and len(quota) > 0:
            result = True
        elif drive_id and owner:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}
    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
