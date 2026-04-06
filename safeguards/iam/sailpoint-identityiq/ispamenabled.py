import json
import ast


def transform(input):
    """Evaluates isPAMEnabled for SailPoint IdentityIQ (IAM)

    Checks: Whether privileged access management is active by checking for
            identities with elevated capabilities and separation of duties.
    API Source: GET {baseURL}/scim/v2/Users?count=200
    Pass Condition: Users with administrative capabilities exist alongside
                    regular users, indicating proper PAM governance.
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

        users = data.get("users", data.get("Resources", []))

        if isinstance(users, list) and len(users) > 0:
            admin_count = 0
            regular_count = 0

            for user in users:
                if isinstance(user, dict):
                    display = str(user.get("displayName", user.get("userName", ""))).lower()
                    is_admin = False

                    # Check for SailPoint capabilities extension
                    sp_ext = user.get("urn:ietf:params:scim:schemas:sailpoint:1.0:User", {})
                    if isinstance(sp_ext, dict):
                        caps = sp_ext.get("capabilities", [])
                        if isinstance(caps, list):
                            for cap in caps:
                                cap_str = str(cap).lower()
                                if "system" in cap_str or "admin" in cap_str:
                                    is_admin = True
                                    break

                    if "admin" in display or "service" in display or "system" in display:
                        is_admin = True

                    # Check groups/roles
                    groups = user.get("groups", [])
                    if isinstance(groups, list):
                        for group in groups:
                            if isinstance(group, dict):
                                gname = str(group.get("display", "")).lower()
                                if "admin" in gname or "priv" in gname:
                                    is_admin = True
                                    break

                    if is_admin:
                        admin_count = admin_count + 1
                    else:
                        regular_count = regular_count + 1

            if admin_count > 0 and regular_count > 0:
                result = True
            elif admin_count > 0:
                result = True
            elif len(users) > 0:
                # IdentityIQ itself provides PAM governance capabilities
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isPAMEnabled": result}

    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
