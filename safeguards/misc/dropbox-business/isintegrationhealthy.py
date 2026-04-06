import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Dropbox Business (Enterprise Cloud Storage)

    Checks: Whether the Dropbox Business API is responding with valid authentication
    API Source: POST https://api.dropboxapi.com/2/team/get_info
    Pass Condition: API returns a valid team response confirming connectivity

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean}
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

        team_id = data.get("team_id", data.get("teamId", ""))
        name = data.get("name", "")
        error = data.get("error", None)

        if error:
            result = False
        elif team_id or name:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isIntegrationHealthy": result}
    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
