import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for VMware vSphere (Network Security)"""
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

        # vSphere host list: check all hosts are connected and powered on (healthy state)
        hosts = data if isinstance(data, list) else data.get("value", [])
        if isinstance(hosts, list) and len(hosts) > 0:
            all_healthy = True
            for host in hosts:
                if isinstance(host, dict):
                    conn = host.get("connection_state", "")
                    power = host.get("power_state", "")
                    if conn != "CONNECTED" or power != "POWERED_ON":
                        all_healthy = False
                        break
            result = all_healthy
        elif isinstance(data, dict):
            cpu = data.get("cpuUsage", data.get("cpu_usage", None))
            mem = data.get("memoryUsage", data.get("memory_usage", None))
            if cpu is not None and mem is not None:
                try:
                    result = float(cpu) < 50 and float(mem) < 50
                except (ValueError, TypeError):
                    result = False

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
