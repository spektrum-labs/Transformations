import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Panther SIEM

    Checks: Whether Panther has active log sources configured by verifying
            the log-sources endpoint returns at least one healthy source.

    API Source: GET {baseURL}/v1/log-sources
    Pass Condition: At least one log source exists with a healthy/active status,
                    confirming data is being ingested into Panther.

    Parameters:
        input (dict): JSON data containing API response from the log-sources endpoint

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

        # Panther returns log sources as a list or under results key
        sources = data if isinstance(data, list) else data.get("results", data.get("logSources", data.get("data", [])))
        if not isinstance(sources, list):
            sources = []

        total_count = len(sources)
        active_count = 0

        for source in sources:
            health = source.get("health", source.get("status", ""))
            is_enabled = source.get("isEnabled", source.get("enabled", None))

            if is_enabled is False:
                continue
            if str(health).lower() in ("healthy", "active", "ok", "running", ""):
                active_count += 1

        result = active_count > 0

        return {
            "isLogIngestionActive": result,
            "activeSourceCount": active_count,
            "totalSourceCount": total_count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
