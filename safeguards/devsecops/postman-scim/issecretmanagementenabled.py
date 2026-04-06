import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Postman SCIM (SCIM Provisioning)

    Checks: Whether the SCIM service provider configuration is active and accessible
    API Source: GET https://api.getpostman.com/scim/v2/ServiceProviderConfig
    Pass Condition: SCIM config shows authentication schemes are configured

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

        # -- EVALUATION LOGIC --
        result = False

        # Check for authentication schemes in SCIM service provider config
        auth_schemes = data.get("authenticationSchemes", [])
        if isinstance(auth_schemes, list) and len(auth_schemes) > 0:
            result = True
        elif data.get("schemas") and data.get("patch"):
            result = True
        elif data.get("documentationUri"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
