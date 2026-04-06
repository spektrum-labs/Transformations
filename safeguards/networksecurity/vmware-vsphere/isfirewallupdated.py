import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for VMware vSphere (Network Security)"""
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

        # vSphere /api/vcenter/host returns ESXi hosts with connection and power state
        hosts = data if isinstance(data, list) else data.get("value", [])
        if isinstance(hosts, list) and len(hosts) > 0:
            for host in hosts:
                if isinstance(host, dict):
                    conn = host.get("connection_state", "")
                    power = host.get("power_state", "")
                    if conn == "CONNECTED" and power == "POWERED_ON":
                        result = True
                        break
        elif isinstance(data, dict) and data.get("connection_state", "") == "CONNECTED":
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
