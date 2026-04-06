import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Forescout (Network Security)"""
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

        # Forescout host data: check for performance metrics indicating healthy operation
        hosts = data.get("hosts", [])
        if isinstance(hosts, list) and len(hosts) > 0:
            # If host data is returned, platform is responsive and performant
            result = True
        elif isinstance(data, dict):
            cpu = data.get("cpuUsage", data.get("cpu_usage", None))
            mem = data.get("memoryUsage", data.get("memory_usage", None))
            if cpu is not None and mem is not None:
                try:
                    result = float(cpu) < 50 and float(mem) < 50
                except (ValueError, TypeError):
                    result = False
            elif data.get("status", "").lower() in ("ok", "healthy", "active"):
                result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
