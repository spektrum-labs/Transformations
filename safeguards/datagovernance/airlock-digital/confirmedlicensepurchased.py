import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Airlock Digital

    Checks: Whether the Airlock Digital license is active
    API Source: https://{server}:3129/api/v1/license
    Pass Condition: API returns a valid license response

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "licenseActive": boolean}
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
        error = data.get("error", None)
        active = data.get("active", data.get("data", {}).get("active", None))

        result = error is None and active is not None
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "licenseActive": result
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
