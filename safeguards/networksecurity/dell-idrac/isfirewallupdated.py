import json
import ast


def transform(input):
    """Evaluates isFirewallUpdated for Dell iDRAC (Network Security)"""
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

        # Redfish /Systems/System.Embedded.1 returns BiosVersion, FirmwareVersion
        bios_version = data.get("BiosVersion", "")
        firmware_version = data.get("FirmwareVersion", "")
        status_obj = data.get("Status", {})

        # Check system health state indicates operational firmware
        health = ""
        if isinstance(status_obj, dict):
            health = status_obj.get("Health", "")

        if isinstance(health, str) and health.lower() == "ok":
            result = True
        elif bios_version and isinstance(bios_version, str) and len(bios_version) > 0:
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallUpdated": result}

    except Exception as e:
        return {"isFirewallUpdated": False, "error": str(e)}
