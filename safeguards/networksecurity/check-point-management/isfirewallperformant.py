import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Check Point Management (Network Security)"""
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

        # show-gateways-and-servers returns objects with health and SIC status
        objects = data.get("objects", [])

        if isinstance(objects, list) and len(objects) > 0:
            all_healthy = True
            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                sic_state = obj.get("sic-state", obj.get("sic_state", ""))
                if isinstance(sic_state, str) and sic_state.lower() not in ("communicating", "initialized", ""):
                    all_healthy = False
                    break
            result = all_healthy
        else:
            # Fallback: check for top-level CPU/memory metrics
            cpu_usage = data.get("cpuUsage", data.get("cpu_usage", None))
            memory_usage = data.get("memoryUsage", data.get("memory_usage", None))
            if cpu_usage is not None and memory_usage is not None:
                try:
                    if float(cpu_usage) < 50 and float(memory_usage) < 50:
                        result = True
                except (ValueError, TypeError):
                    pass

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
