import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for F5 (Network Security)"""
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

        # F5 /mgmt/tm/sys/version returns entries with version/build info
        entries = data.get("entries", {})

        if isinstance(entries, dict) and len(entries) > 0:
            for key, val in entries.items():
                if isinstance(val, dict):
                    nested = val.get("nestedStats", {})
                    if isinstance(nested, dict):
                        inner = nested.get("entries", {})
                        version_entry = inner.get("Version", inner.get("version", {}))
                        if isinstance(version_entry, dict):
                            desc = version_entry.get("description", "")
                            if desc and isinstance(desc, str) and len(desc) > 0:
                                result = True
                                break

        if not result:
            # Fallback: check top-level version
            version = data.get("version", data.get("Version", ""))
            if version and isinstance(version, str) and len(version) > 0:
                result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
