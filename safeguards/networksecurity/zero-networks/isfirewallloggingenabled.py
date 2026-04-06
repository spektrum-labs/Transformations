import json
import ast


def transform(input):
    """Evaluates isFirewallLoggingEnabled for Zero Networks (Network Security)"""
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

        # Zero Networks /api/v1/audit returns audit log entries
        items = data.get("items", data.get("results", data.get("events", [])))
        if isinstance(items, list) and len(items) > 0:
            result = True
        elif isinstance(data, list) and len(data) > 0:
            result = True
        elif isinstance(data, dict) and data.get("totalCount", data.get("total", 0)) > 0:
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallLoggingEnabled": result}

    except Exception as e:
        return {"isFirewallLoggingEnabled": False, "error": str(e)}
