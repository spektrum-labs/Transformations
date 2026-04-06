import json
import ast


def transform(input):
    """
    Evaluates isLifeCycleManagementEnabled for Authomize (IAM)

    Checks: Whether proper identity lifecycle with orphan account detection and deprovisioning exists
    API Source: GET {baseURL}/v2/identities
    Pass Condition: Identities show lifecycle state indicators such as orphan detection or status tracking
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

        identities = data.get("identities", data.get("data", data.get("items", [])))

        if isinstance(identities, list) and len(identities) > 0:
            has_status_tracking = False
            has_orphan_detection = False

            for identity in identities:
                # Check for lifecycle status tracking
                status = identity.get("status", identity.get("state", ""))
                if status and str(status).lower() in ("active", "inactive", "disabled", "orphan", "stale"):
                    has_status_tracking = True
                # Check for orphan or stale account detection
                is_orphan = identity.get("isOrphan", identity.get("orphan", False))
                is_stale = identity.get("isStale", identity.get("stale", False))
                last_activity = identity.get("lastActivity", identity.get("lastSeen", None))

                if is_orphan or is_stale:
                    has_orphan_detection = True
                if last_activity is not None:
                    has_status_tracking = True

            result = has_status_tracking or has_orphan_detection
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
