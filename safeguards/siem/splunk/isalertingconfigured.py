import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Splunk SIEM

    Checks: Whether scheduled saved searches (alerts) are configured in
            Splunk by checking for active scheduled searches.

    API Source: GET {baseURL}/services/saved/searches?output_mode=json&search=is_scheduled%3D1
    Pass Condition: At least one scheduled saved search exists, confirming
                    that alerting is configured for security monitoring.

    Parameters:
        input (dict): JSON data containing API response from the saved searches endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "scheduledSearchCount": int}
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

        # Splunk saved searches are under entry array
        entries = data.get("entry", data.get("entries", []))
        if not isinstance(entries, list):
            entries = []

        scheduled_count = 0

        for entry in entries:
            content = entry.get("content", entry)
            is_scheduled = content.get("is_scheduled", content.get("isScheduled", False))
            disabled = content.get("disabled", False)

            if (is_scheduled or str(is_scheduled) == "1") and not disabled:
                scheduled_count += 1

        # If we queried with is_scheduled=1 filter, all returned entries are scheduled
        if scheduled_count == 0 and len(entries) > 0:
            scheduled_count = len(entries)

        result = scheduled_count > 0

        return {
            "isAlertingConfigured": result,
            "scheduledSearchCount": scheduled_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
