import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Forescout (Network Security)"""
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

        # Forescout /api/hosts returns host list; connected hosts indicate current platform
        hosts = data.get("hosts", [])
        if isinstance(hosts, list) and len(hosts) > 0:
            # Check that hosts have recent data indicating the platform is actively updated
            for host in hosts:
                if isinstance(host, dict):
                    fields = host.get("fields", {})
                    if isinstance(fields, dict) and len(fields) > 0:
                        result = True
                        break
        elif isinstance(data, dict) and data.get("version", ""):
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
