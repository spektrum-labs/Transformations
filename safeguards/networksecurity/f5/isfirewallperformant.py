import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for F5 (Network Security)"""
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

        # F5 /mgmt/tm/sys/version returns system info; performance data
        # may include CPU and memory utilization
        entries = data.get("entries", {})

        if isinstance(entries, dict) and len(entries) > 0:
            # Version info present indicates system is responsive
            result = True
        else:
            # Fallback: check for direct performance metrics
            cpu_usage = data.get("cpuUsage", data.get("oneMinAvgSystem", None))
            memory_usage = data.get("memoryUsage", data.get("tmmMemoryUsed", None))

            if cpu_usage is not None and memory_usage is not None:
                try:
                    if float(cpu_usage) < 50 and float(memory_usage) < 50:
                        result = True
                except (ValueError, TypeError):
                    pass
            elif isinstance(data, dict) and len(data) > 0:
                # Valid response from version endpoint means system is operational
                kind = data.get("kind", "")
                if isinstance(kind, str) and "sys" in kind.lower():
                    result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
