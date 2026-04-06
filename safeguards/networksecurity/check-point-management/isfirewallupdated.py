import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Check Point Management (Network Security)"""
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

        # show-gateways-and-servers returns objects with version and SIC status
        objects = data.get("objects", [])

        if isinstance(objects, list) and len(objects) > 0:
            all_updated = True
            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                sic_state = obj.get("sic-state", obj.get("sic_state", ""))
                if isinstance(sic_state, str) and sic_state.lower() not in ("communicating", "initialized", ""):
                    all_updated = False
                    break
            result = all_updated
        else:
            # Fallback: check for version info at top level
            version = data.get("version", "")
            if version and isinstance(version, str) and len(version) > 0:
                result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
