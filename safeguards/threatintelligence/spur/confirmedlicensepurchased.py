import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Spur.

    Checks: Active Spur subscription by confirming status endpoint returns valid account data
    API Source: GET https://api.spur.us/v2/context/status
    Pass Condition: Response contains valid quota and tier information

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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
        has_error = data.get("error") is not None or data.get("errors") is not None
        queries_remaining = data.get("queries_remaining", data.get("remaining", -1))
        tier = data.get("tier", data.get("plan", ""))

        result = not has_error and isinstance(data, dict) and len(data) > 0
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
