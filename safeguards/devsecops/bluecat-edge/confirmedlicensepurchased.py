import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for BlueCat Edge (DNS Edge Service)

    Checks: Whether BlueCat Edge service points are accessible and active
    API Source: GET {baseURL}/v1/api/servicePoints
    Pass Condition: API returns valid service point data confirming active subscription

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

        # Check for valid service point data indicating active license
        if isinstance(data, list) and len(data) > 0:
            result = True
        elif isinstance(data, dict):
            service_points = data.get("servicePoints", data.get("data", []))
            if isinstance(service_points, list) and len(service_points) > 0:
                result = True
            elif data.get("id") or data.get("name") or data.get("status"):
                result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
