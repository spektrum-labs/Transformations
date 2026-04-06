import json
import ast


def transform(input):
    """Evaluates isFirewallLoggingEnabled for Dell iDRAC (Network Security)"""
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

        # iDRAC SEL (System Event Log) Entries returns Members array
        members = data.get("Members", data.get("members", []))
        members_count = data.get("Members@odata.count", 0)

        if isinstance(members, list) and len(members) > 0:
            result = True
        elif members_count and int(members_count) > 0:
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallLoggingEnabled": result}

    except Exception as e:
        return {"isFirewallLoggingEnabled": False, "error": str(e)}
