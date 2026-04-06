import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Infoblox Cloud Services Portal (Network Security)"""
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

        # Infoblox /api/infra/v1/hosts returns on-prem host agents with version info
        results = data.get("results", [])
        if isinstance(results, list) and len(results) > 0:
            for host in results:
                if isinstance(host, dict):
                    state = host.get("composite_status", host.get("status", ""))
                    if isinstance(state, str) and state.lower() in ("online", "active", "ok"):
                        result = True
                        break
        elif isinstance(data, dict) and data.get("status", "").lower() in ("online", "active"):
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
