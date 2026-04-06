import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Nutanix Hypervisor (Network Security)"""
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

        # Nutanix /api/nutanix/v3/clusters/list returns cluster entities with version info
        entities = data.get("entities", [])
        if isinstance(entities, list) and len(entities) > 0:
            for entity in entities:
                if isinstance(entity, dict):
                    status = entity.get("status", {})
                    if isinstance(status, dict):
                        resources = status.get("resources", {})
                        build = resources.get("build", {})
                        version = build.get("version", resources.get("version", ""))
                        if version:
                            result = True
                            break
        elif isinstance(data, dict) and data.get("status", {}).get("state", "") == "COMPLETE":
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
