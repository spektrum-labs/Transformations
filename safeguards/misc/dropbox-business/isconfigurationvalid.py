import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for Dropbox Business (Enterprise Cloud Storage)

    Checks: Whether the Dropbox Business team info and license counts are accessible
    API Source: POST https://api.dropboxapi.com/2/team/get_info
    Pass Condition: API returns valid team configuration with license information

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

        team_id = data.get("team_id", data.get("teamId", ""))
        name = data.get("name", "")
        num_licensed = data.get("num_licensed_users", data.get("numLicensedUsers", 0))
        num_provisioned = data.get("num_provisioned_users", data.get("numProvisionedUsers", 0))

        if team_id and name:
            result = True
        elif num_licensed or num_provisioned:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}
    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
