import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for OneDrive (Microsoft Cloud Storage)

    Checks: Whether the OneDrive drive information is accessible via Microsoft Graph
    API Source: GET https://graph.microsoft.com/v1.0/users/{userId}/drive
    Pass Condition: API returns a valid drive object with driveId and driveType

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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
        owner = data.get("owner", {})

        if drive_id or drive_type:
            result = True
        elif isinstance(owner, dict) and owner.get("user"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
