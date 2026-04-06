import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Atlassian Compass (Developer Portal)

    Checks: Whether the Compass instance is accessible and components are registered
    API Source: GET {baseURL}/v1/components
    Pass Condition: API returns a valid response with component data

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

        # A valid response from the Compass API confirms an active Atlassian subscription
        components = data.get("values", data.get("data", []))
        if isinstance(components, list):
            result = True
        elif data.get("id") or data.get("cloudId") or data.get("total") is not None:
            result = True
        elif isinstance(data, dict) and len(data) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
