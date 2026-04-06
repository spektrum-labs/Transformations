import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Postman SCIM (SCIM Provisioning)

    Checks: Whether SCIM user provisioning is active with provisioned users
    API Source: GET https://api.getpostman.com/scim/v2/Users
    Pass Condition: At least one SCIM-provisioned user exists

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

        # Check for SCIM-provisioned users
        resources = data.get("Resources", data.get("resources", []))
        total = data.get("totalResults", data.get("total_results", 0))

        if isinstance(resources, list) and len(resources) > 0:
            result = True
        elif total > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
