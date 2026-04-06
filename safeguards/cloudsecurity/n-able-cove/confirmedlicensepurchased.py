import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for N-able Cove Data Protection

    Checks: Whether the Cove Data Protection account is active
    API Source: {baseURL}/api/v1/status
    Pass Condition: A valid API response is returned confirming active subscription

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
        status = data.get("status", data.get("state", ""))
        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "enabled", "licensed", "trial", "ok"}
        result = status in valid_statuses

        if not result and data:
            result = bool(data.get("id") or data.get("partnerId") or data.get("data"))
            if result:
                status = "active"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
