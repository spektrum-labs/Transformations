import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for AlertMedia

    Checks: Whether the AlertMedia API is responding and service is healthy
    API Source: https://api.alertmedia.com/api/v3/status
    Pass Condition: Status response indicates healthy or active service

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
            status = status.lower()

        valid_statuses = {"ok", "healthy", "active", "operational"}
        result = status in valid_statuses or healthy is True
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "status": status
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
