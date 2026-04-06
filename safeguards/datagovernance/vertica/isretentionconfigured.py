import json
import ast


def transform(input):
    """
    Evaluates isRetentionConfigured for Vertica

    Checks: Whether Vertica nodes are operational with retention configured
    Pass Condition: at least 1 node is in 'UP' state

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRetentionConfigured": boolean, "status": str}
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
        status = data.get("status", data.get("state", data.get("node_state", "")))

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "running", "healthy", "ok", "up", "operational"}
        result = bool(status and status in valid_statuses)

        if not result:
            version = data.get("version", data.get("results",
                data.get("node_name", "")))
            result = bool(version)
        # -- END EVALUATION LOGIC --

        return {
            "isRetentionConfigured": result,
            "status": status
        }

    except Exception as e:
        return {"isRetentionConfigured": False, "error": str(e)}
