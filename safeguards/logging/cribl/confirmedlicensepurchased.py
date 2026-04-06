import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Cribl

    Checks: Whether the Cribl instance is licensed and operational
    API Source: https://{workspace}.cribl.cloud/api/v1/system/info
    Pass Condition: API returns system info confirming a licensed instance

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "accountActive": boolean}
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
        licensed = data.get("licensed", data.get("license", data.get("version", None)))

        result = error is None and licensed is not None
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "accountActive": result
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
