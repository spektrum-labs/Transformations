import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Fastly (Network Security)"""
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

        # Fastly /service returns list of services with version info
        # Each service has an active version number indicating current config
        if isinstance(data, list) and len(data) > 0:
            for svc in data:
                if isinstance(svc, dict):
                    active_version = svc.get("active_version", svc.get("version", None))
                    if active_version is not None:
                        result = True
                        break
        elif isinstance(data, dict):
            # Single service response
            versions = data.get("versions", [])
            active_version = data.get("active_version", None)
            if active_version is not None:
                result = True
            elif isinstance(versions, list) and len(versions) > 0:
                result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
