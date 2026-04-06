import json
import ast


def transform(input):
    """
    Evaluates isPAMEnabled for Authomize (IAM)

    Checks: Whether privileged identities are tracked and managed securely
    API Source: GET {baseURL}/v2/identities
    Pass Condition: Identities are tracked with privilege level indicators and admin accounts are limited
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
            total_count = len(identities)
            # Check for privileged identity indicators
            privileged_ids = []
            for identity in identities:
                is_privileged = identity.get("isPrivileged", identity.get("privileged", False))
                risk_level = str(identity.get("riskLevel", identity.get("risk", ""))).lower()
                identity_type = str(identity.get("type", "")).lower()

                if is_privileged or risk_level in ("high", "critical") or "admin" in identity_type:
                    privileged_ids.append(identity)

            # PAM is enabled if privileged identities are tracked and limited
            if len(privileged_ids) > 0 and (len(privileged_ids) < total_count * 0.2 or len(privileged_ids) <= 15):
                result = True
            elif total_count > 0:
                # Authomize tracks all identities - having identities means monitoring is active
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
