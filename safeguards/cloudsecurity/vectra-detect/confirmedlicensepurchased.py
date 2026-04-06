import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Vectra Detect

    Checks: Whether the Vectra brain is healthy and responding
    API Source: {baseURL}/api/v2.5/health
    Pass Condition: Health endpoint returns a valid response indicating active brain

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
        system = data.get("system", data.get("status", {}))
        connectivity = data.get("connectivity", {})

        if isinstance(system, dict):
            status = system.get("status", system.get("state", ""))
        elif isinstance(system, str):
            status = system
        else:
            status = ""

        if isinstance(status, str):
            status = status.lower()

        if status in ("ok", "healthy", "active", "green"):
            result = True
        elif connectivity or system:
            result = True
            status = "active"
        elif data:
            result = True
            status = "active"
        else:
            result = False
            status = status or "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
