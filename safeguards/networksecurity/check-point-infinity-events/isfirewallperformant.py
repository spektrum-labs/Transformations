import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Check Point Infinity Events (Network Security)"""
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

        # Infinity Events status returns service health and processing metrics
        status = data.get("status", "")
        cpu_usage = data.get("cpuUsage", data.get("cpu_usage", None))
        memory_usage = data.get("memoryUsage", data.get("memory_usage", None))

        if cpu_usage is not None and memory_usage is not None:
            try:
                cpu_val = float(cpu_usage)
                mem_val = float(memory_usage)
                if cpu_val < 50 and mem_val < 50:
                    result = True
            except (ValueError, TypeError):
                pass
        elif isinstance(status, str) and status.lower() in ("ok", "healthy", "active", "running"):
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
