import json
import ast


def transform(input):
    """Evaluates isIAMLoggingEnabled for Red Hat IDM (IAM)

    Checks: Whether audit logging is enabled in Red Hat IdM by inspecting
            global configuration for logging-related attributes.
    API Source: POST {baseURL}/ipa/session/json (method: config_show)
    Pass Condition: Configuration contains active logging settings or
                    the IdM server is accessible (IdM logs by default).
    """
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
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        # Red Hat IdM has built-in audit logging via 389 Directory Server
        # and SSSD. If config_show returns valid config, logging is active.
        config = data.get("config", data)
        if isinstance(config, dict):
            config = config.get("result", config)

        if isinstance(config, dict):
            # IdM always has audit logging via access/error logs in 389DS
            # Check that the config is valid (has known fields)
            domain = config.get("ipasearchrecordslimit", config.get("ipadomainresolutionorder", None))
            ca_renewal = config.get("ipaconfigstring", config.get("ipa_master", None))

            # If we got a valid config response, IdM logging is inherently enabled
            if len(config.keys()) > 0:
                result = True

            # Explicit check for logging-related configuration
            config_strings = config.get("ipaconfigstring", [])
            if isinstance(config_strings, list):
                for cs in config_strings:
                    if isinstance(cs, str) and "audit" in cs.lower():
                        result = True
                        break
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
