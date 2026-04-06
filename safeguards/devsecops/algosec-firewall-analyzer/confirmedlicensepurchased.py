import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for AlgoSec Firewall Analyzer

    Checks: Whether the AlgoSec instance returns a valid devices response indicating active license
    API Source: {baseURL}/afa/api/v1/devices
    Pass Condition: API returns a successful response with device data

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
        status = data.get("status", "")

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "trial", "enabled"}
        result = status in valid_statuses

        if not result:
            licensed = data.get("licensePurchased", data.get("active", None))
            if isinstance(licensed, bool):
                result = licensed
            elif isinstance(licensed, str):
                result = licensed.lower() in ("true", "active", "enabled")

        if not result:
            devices = data.get("devices", data.get("data", data.get("results", [])))
            if isinstance(devices, list) and len(devices) > 0:
                result = True
                status = "active"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status if isinstance(status, str) else str(status)
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
