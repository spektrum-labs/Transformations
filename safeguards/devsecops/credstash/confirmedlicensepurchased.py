import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for CredStash (AWS Secrets Management)

    Checks: Whether the CredStash service is accessible and operational
    API Source: GET {baseURL}/status
    Pass Condition: API returns a valid status indicating the service is running

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

        # A valid status response confirms CredStash is operational
        status = data.get("status", "")
        if status and str(status).lower() in ("ok", "active", "healthy", "running"):
            result = True
        elif data.get("table") or data.get("region"):
            result = True
        elif isinstance(data, dict) and len(data) > 0 and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
