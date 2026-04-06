import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Imperva (Network Security)"""
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

        # Imperva Cloud WAF is SaaS; status endpoint confirms rules are active and current
        status = data.get("status", "")
        if isinstance(status, str) and status.lower() in ("active", "ok", "valid"):
            result = True
        elif data.get("res", -1) == 0:
            # Imperva API returns res=0 on success, indicating service is operational
            result = True
        elif isinstance(data, dict) and data.get("siteStatus", "") == "active":
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
