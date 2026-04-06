import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for OneLogin (IAM)

    Checks that MFA is enforced for OneLogin users by inspecting
    OTP-related authentication factors on user records.

    Parameters:
        input (dict): JSON data containing API response from getEstateMFAStatus

    Returns:
        dict: {"isStrongAuthRequired": boolean}
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

        users = data.get("data", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            mfa_count = 0
            total_active = 0
            for user in users:
                status = user.get("status", 0)
                # OneLogin status 1 = Active
                if status != 1 and status != "Active":
                    continue
                total_active += 1
                otp_devices = user.get("otp_devices", [])
                auth_factor = user.get("auth_factor", None)
                if isinstance(otp_devices, list) and len(otp_devices) > 0:
                    mfa_count += 1
                elif auth_factor is not None and auth_factor != "":
                    mfa_count += 1
            if total_active > 0:
                result = mfa_count >= total_active * 0.5
        elif isinstance(data, list) and len(data) > 0:
            # Direct array of MFA enrollment records
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
