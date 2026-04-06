import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Securonix SIEM

    Checks: Whether Securonix has active data sources configured and ingesting
            logs by verifying the datasources endpoint returns enabled sources.

    API Source: GET {baseURL}/ws/datasources/get
    Pass Condition: At least one data source exists and is enabled, confirming
                    log ingestion is active in Securonix SNYPR.

    Parameters:
        input (dict): JSON data containing API response from the datasources endpoint

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

        # Securonix datasources returns a list of configured sources
        sources = data if isinstance(data, list) else data.get("data", data.get("datasources", data.get("result", [])))
        if not isinstance(sources, list):
            sources = []

        total_count = len(sources)
        active_count = 0

        for source in sources:
            status = source.get("status", source.get("State", ""))
            enabled = source.get("enabled", source.get("isEnabled", None))

            if enabled is False:
                continue
            if str(status).lower() in ("active", "enabled", "running", "online", ""):
                active_count += 1

        result = active_count > 0

        return {
            "isLogIngestionActive": result,
            "activeSourceCount": active_count,
            "totalSourceCount": total_count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
