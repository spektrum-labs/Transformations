import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Check Point Harmony (Network Security)"""
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

        # Harmony Endpoint status returns protection status and update info
        status = data.get("status", "")
        update_status = data.get("updateStatus", data.get("update_status", ""))
        version = data.get("version", data.get("clientVersion", ""))

        if isinstance(status, str) and status.lower() in ("up_to_date", "updated", "ok", "active"):
            result = True
        elif isinstance(update_status, str) and update_status.lower() in ("up_to_date", "updated", "current"):
            result = True
        elif version and isinstance(version, str) and len(version) > 0:
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
