import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Postman SCIM (SCIM Provisioning)

    Checks: Whether the Postman SCIM service provider configuration is accessible
    API Source: GET https://api.getpostman.com/scim/v2/ServiceProviderConfig
    Pass Condition: API returns a valid SCIM service provider config confirming Enterprise plan

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

        # A valid ServiceProviderConfig response confirms SCIM is enabled (Enterprise plan)
        schemas = data.get("schemas", [])
        if isinstance(schemas, list) and len(schemas) > 0:
            result = True
        elif data.get("patch") or data.get("bulk") or data.get("filter"):
            result = True
        elif data.get("documentationUri") or data.get("authenticationSchemes"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
