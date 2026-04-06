import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Sumo Logic SIEM

    Checks: Whether Sumo Logic has active collectors configured by verifying
            the collectors endpoint returns at least one alive collector.

    API Source: GET {baseURL}/v1/collectors?limit=50
    Pass Condition: At least one collector exists with an alive status,
                    confirming log ingestion is active.

    Parameters:
        input (dict): JSON data containing API response from the collectors endpoint

    Returns:
        dict: {"isLogIngestionActive": boolean, "aliveCollectorCount": int, "totalCollectorCount": int}
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

        # Sumo Logic returns collectors under collectors array
        collectors = data.get("collectors", data.get("data", []))
        if not isinstance(collectors, list):
            collectors = []

        total_count = len(collectors)
        alive_count = 0

        for collector in collectors:
            is_alive = collector.get("alive", collector.get("isAlive", None))
            status = collector.get("status", "")

            if is_alive is True or str(status).lower() in ("active", "alive", "online"):
                alive_count += 1

        result = alive_count > 0

        return {
            "isLogIngestionActive": result,
            "aliveCollectorCount": alive_count,
            "totalCollectorCount": total_count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
