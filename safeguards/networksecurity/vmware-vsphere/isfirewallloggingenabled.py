import json
import ast


def transform(input):
    """Evaluates isFirewallLoggingEnabled for VMware vSphere (Network Security)"""
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

        # vSphere /api/appliance/logging/forwarding returns syslog forwarding configs
        forwarding = data if isinstance(data, list) else data.get("value", [])
        if isinstance(forwarding, list) and len(forwarding) > 0:
            for entry in forwarding:
                if isinstance(entry, dict):
                    hostname = entry.get("hostname", entry.get("server", ""))
                    if hostname:
                        result = True
                        break
        elif isinstance(data, dict) and data.get("hostname", ""):
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallLoggingEnabled": result}

    except Exception as e:
        return {"isFirewallLoggingEnabled": False, "error": str(e)}
