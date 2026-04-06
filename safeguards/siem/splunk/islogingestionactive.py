import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Splunk SIEM

    Checks: Whether Splunk has active data inputs configured by verifying
            the inputs endpoint returns at least one enabled data source.

    API Source: GET {baseURL}/services/data/inputs/all?output_mode=json&count=50
    Pass Condition: At least one data input is configured and not disabled,
                    confirming log ingestion is active.

    Parameters:
        input (dict): JSON data containing API response from the data inputs endpoint

    Returns:
        dict: {"isLogIngestionActive": boolean, "activeInputCount": int, "totalInputCount": int}
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

        # Splunk data inputs are under entry array
        entries = data.get("entry", data.get("entries", []))
        if not isinstance(entries, list):
            entries = []

        total_count = len(entries)
        active_count = 0

        for entry in entries:
            content = entry.get("content", entry)
            disabled = content.get("disabled", False)

            if not disabled:
                active_count += 1

        result = active_count > 0

        return {
            "isLogIngestionActive": result,
            "activeInputCount": active_count,
            "totalInputCount": total_count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
