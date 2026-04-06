import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Atlassian User Provisioning (SCIM)

    Checks: Whether the SCIM ServiceProviderConfig endpoint returns valid data
    API Source: https://api.atlassian.com/scim/directory/{directoryId}/ServiceProviderConfig
    Pass Condition: A valid SCIM service provider configuration is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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
        schemas = data.get("schemas", [])
        patch_supported = data.get("patch", {}).get("supported", False)

        result = bool(schemas) or bool(patch_supported)
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": "unknown",
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
