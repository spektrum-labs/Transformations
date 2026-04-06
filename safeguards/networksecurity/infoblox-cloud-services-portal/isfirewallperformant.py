import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Infoblox Cloud Services Portal (Network Security)"""
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

        # Infoblox hosts endpoint returns health status for on-prem agents
        results = data.get("results", [])
        if isinstance(results, list) and len(results) > 0:
            healthy_count = 0
            total_count = len(results)
            for host in results:
                if isinstance(host, dict):
                    state = host.get("composite_status", host.get("status", ""))
                    if isinstance(state, str) and state.lower() in ("online", "active", "ok"):
                        healthy_count += 1
            if total_count > 0 and healthy_count == total_count:
                result = True
        elif isinstance(data, dict) and data.get("status", "").lower() in ("online", "healthy"):
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
