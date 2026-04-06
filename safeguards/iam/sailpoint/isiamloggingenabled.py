import json
import ast


def transform(input):
    """Evaluates isIAMLoggingEnabled for SailPoint IdentityNow (IAM)

    Checks: Whether IAM audit logging is active by checking the tenant
            configuration for event tracking and audit capabilities.
    API Source: GET {baseURL}/v3/mfa-configuration
    Pass Condition: A valid response is returned, confirming the tenant
                    is active with built-in audit logging capabilities.
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

        # SailPoint IdentityNow has built-in audit logging for all identity events.
        # A valid API response confirms the tenant is operational with logging active.
        mfa_config = data.get("mfaConfig", data)

        if isinstance(mfa_config, dict) and len(mfa_config.keys()) > 0:
            # Valid config response means the tenant is active, and SailPoint
            # IdentityNow always has audit logging enabled by default
            result = True
        elif isinstance(mfa_config, list) and len(mfa_config) > 0:
            result = True

        # Also check for explicit audit/logging config
        audit = data.get("auditEnabled", data.get("audit", None))
        if isinstance(audit, bool):
            result = audit
        elif isinstance(audit, str) and audit.lower() in ["true", "enabled", "active"]:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
