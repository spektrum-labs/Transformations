import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Beeceptor (API Mocking)

    Checks: Whether the Beeceptor account has an active subscription with API access
    API Source: GET https://app.beeceptor.com/api/v2/endpoints
    Pass Condition: API returns a valid list of endpoints confirming active Team plan or higher

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

        # ── EVALUATION LOGIC ──
        result = False

        # A valid response from /api/v2/endpoints confirms active subscription
        if isinstance(data, list) and len(data) > 0:
            result = True
        elif isinstance(data, dict):
            endpoints = data.get("endpoints", data.get("data", []))
            if isinstance(endpoints, list) and len(endpoints) > 0:
                result = True
            elif data.get("name") or data.get("id"):
                result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
