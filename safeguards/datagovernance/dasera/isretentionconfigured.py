import json
import ast


def transform(input):
    """
    Evaluates isRetentionConfigured for Dasera

    Checks: Whether the Dasera platform indicates active governance
    Pass Condition: status is 'active' or 'healthy'

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
        status = data.get("status", data.get("state", ""))

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "running", "healthy", "ok", "up", "operational"}
        result = bool(status and status in valid_statuses)

        if not result:
            version = data.get("version", data.get("netbox-version",
                data.get("neo4j_version", data.get("cluster_id", ""))))
            result = bool(version)
        # -- END EVALUATION LOGIC --

        return {
            "isRetentionConfigured": result,
            "status": status
        }

    except Exception as e:
        return {"isRetentionConfigured": False, "error": str(e)}
