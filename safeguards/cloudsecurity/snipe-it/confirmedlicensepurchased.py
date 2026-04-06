import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Snipe-IT

    Checks: Whether the Snipe-IT instance returns valid license records
    API Source: {baseURL}/licenses
    Pass Condition: At least one license record exists in the response

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
        total = data.get("total", 0)
        rows = data.get("rows", [])

        if isinstance(rows, list) and len(rows) > 0:
            result = True
            status = "active"
        elif isinstance(total, int) and total > 0:
            result = True
            status = "active"
        else:
            result = False
            status = "no_licenses"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
