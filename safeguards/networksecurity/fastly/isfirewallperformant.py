import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Fastly (Network Security)"""
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

        # Fastly /service returns services; an active service list indicates
        # the edge platform is operational and responsive
        if isinstance(data, list) and len(data) > 0:
            # Check that services have active versions (deployments)
            for svc in data:
                if isinstance(svc, dict):
                    active_version = svc.get("active_version", None)
                    if active_version is not None:
                        result = True
                        break
        elif isinstance(data, dict):
            # Check for error ratios in stats or healthy service status
            error_rate = data.get("errors", data.get("error_rate", None))
            status_val = data.get("status", "")

            if error_rate is not None:
                try:
                    if float(error_rate) < 50:
                        result = True
                except (ValueError, TypeError):
                    pass
            elif isinstance(status_val, str) and status_val.lower() in ("ok", "healthy", "active"):
                result = True
            elif len(data) > 0:
                result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
