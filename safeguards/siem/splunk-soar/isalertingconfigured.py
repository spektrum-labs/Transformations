import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Splunk SOAR

    Checks: Whether playbooks are configured and executing in Splunk SOAR
            by checking the playbook_run endpoint for recent automation runs.

    API Source: GET {baseURL}/rest/playbook_run?page_size=50&sort=id&order=desc
    Pass Condition: At least one playbook run exists, confirming that automation
                    playbooks are configured and actively responding to events.

    Parameters:
        input (dict): JSON data containing API response from the playbook_run endpoint

    Returns:
        dict: {"isAlertingConfigured": boolean, "playbookRunCount": int}
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

        # Splunk SOAR returns playbook runs under data array
        runs = data if isinstance(data, list) else data.get("data", data.get("playbook_runs", []))
        if not isinstance(runs, list):
            count = data.get("count", data.get("num_found", 0))
            if isinstance(count, (int, float)) and count > 0:
                return {
                    "isAlertingConfigured": True,
                    "playbookRunCount": int(count)
                }
            runs = []

        run_count = len(runs)
        result = run_count > 0

        return {
            "isAlertingConfigured": result,
            "playbookRunCount": run_count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
