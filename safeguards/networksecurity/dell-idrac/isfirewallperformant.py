import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Dell iDRAC (Network Security)"""
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
                    raise ValueError("Invalid input")
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
        result = False

        # Redfish /Systems/System.Embedded.1 returns Status with Health info
        # and ProcessorSummary / MemorySummary with utilization
        status_obj = data.get("Status", {})
        health = ""
        if isinstance(status_obj, dict):
            health = status_obj.get("Health", "")

        processor_summary = data.get("ProcessorSummary", {})
        memory_summary = data.get("MemorySummary", {})

        proc_health = ""
        mem_health = ""
        if isinstance(processor_summary, dict):
            proc_status = processor_summary.get("Status", {})
            if isinstance(proc_status, dict):
                proc_health = proc_status.get("Health", "")

        if isinstance(memory_summary, dict):
            mem_status = memory_summary.get("Status", {})
            if isinstance(mem_status, dict):
                mem_health = mem_status.get("Health", "")

        # All health indicators should be "OK" for performant status
        if isinstance(health, str) and health.lower() == "ok":
            if (not proc_health or proc_health.lower() == "ok") and (not mem_health or mem_health.lower() == "ok"):
                result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
