import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for LogRhythm SIEM

    Checks: Whether LogRhythm has active log sources configured and collecting
            data by verifying the log sources endpoint returns enabled sources.

    API Source: GET {baseURL}/lr-admin-api/logsources
    Pass Condition: At least one log source exists with an enabled/active status,
                    confirming log ingestion is operational.

    Parameters:
        input (dict): JSON data containing API response from the logsources endpoint

    Returns:
        dict: {"isLogIngestionActive": boolean, "activeSourceCount": int, "totalSourceCount": int}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # LogRhythm returns log sources as a list
        sources = data if isinstance(data, list) else data.get("data", data.get("logSources", []))
        if not isinstance(sources, list):
            sources = []

        total_count = len(sources)
        active_count = 0

        for source in sources:
            status = source.get("status", source.get("Status", ""))
            enabled = source.get("isEnabled", source.get("IsEnabled", None))

            if enabled is True or str(status).lower() in ("active", "enabled", "ok"):
                active_count += 1

        result = active_count > 0

        return {
            "isLogIngestionActive": result,
            "activeSourceCount": active_count,
            "totalSourceCount": total_count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
