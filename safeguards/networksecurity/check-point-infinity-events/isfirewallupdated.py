import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Check Point Infinity Events (Network Security)"""
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

        # Infinity Events status returns service health and data source status
        status = data.get("status", "")
        version = data.get("version", data.get("engineVersion", ""))
        data_sources = data.get("dataSources", data.get("data_sources", []))

        if isinstance(status, str) and status.lower() in ("active", "ok", "running"):
            result = True
        elif isinstance(data_sources, list) and len(data_sources) > 0:
            result = True
        elif version and isinstance(version, str) and len(version) > 0:
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
