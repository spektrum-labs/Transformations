import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Wazuh Server MDR

    Checks: Whether Wazuh Manager core daemons are running, confirming
            continuous monitoring is active.

    API Source: GET {baseURL}/manager/status
    Pass Condition: Core daemons (wazuh-analysisd, wazuh-remoted) are in a
                    running state, confirming continuous security monitoring.

    Parameters:
        input (dict): JSON data containing API response from the manager status endpoint

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "runningDaemons": int, "totalDaemons": int}
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

        # Wazuh manager/status returns daemon statuses under data.affected_items
        status_data = data.get("data", data)
        affected_items = status_data.get("affected_items", status_data.get("items", []))

        daemons = {}
        if isinstance(affected_items, list) and len(affected_items) > 0:
            daemons = affected_items[0] if isinstance(affected_items[0], dict) else {}
        elif isinstance(status_data, dict) and not affected_items:
            # Direct daemon status map
            daemons = status_data

        # Core daemons that must be running for continuous monitoring
        core_daemons = ["wazuh-analysisd", "wazuh-remoted", "wazuh-syscheckd"]
        running_count = 0
        total_count = 0
        core_running = 0

        for daemon_name, daemon_status in daemons.items():
            if isinstance(daemon_status, str):
                total_count += 1
                if daemon_status.lower() in ("running", "active"):
                    running_count += 1
                    if daemon_name in core_daemons:
                        core_running += 1

        # At least analysisd and remoted must be running
        result = core_running >= 2

        return {
            "isContinuousMonitoringEnabled": result,
            "runningDaemons": running_count,
            "totalDaemons": total_count,
            "coreDaemonsRunning": core_running
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
