import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Infobip

    Checks: Whether the Infobip API service is responding and healthy
    API Source: {baseURL}/status
    Pass Condition: Status endpoint returns OK or healthy response

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "status": str}
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
        healthy = data.get("healthy", False)

        if isinstance(status, str):
            status_lower = status.lower()
        else:
            status_lower = str(status).lower()

        valid_statuses = {"ok", "healthy", "active", "operational"}
        result = status_lower in valid_statuses or healthy is True

        # Infobip /status returns plain "OK" string in some cases
        if not result and isinstance(data, str) and data.strip().upper() == "OK":
            result = True
            status = "ok"
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "status": status
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
