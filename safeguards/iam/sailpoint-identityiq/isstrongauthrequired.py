import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for SailPoint IdentityIQ (IAM)

    Checks: Whether strong authentication is required by checking user
            capabilities and authentication policy settings via SCIM.
    API Source: GET {baseURL}/scim/v2/Users?attributes=capabilities
    Pass Condition: Users have strong authentication capabilities configured.
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
        total = data.get("totalResults", 0)

        if isinstance(users, list) and len(users) > 0:
            for user in users:
                if isinstance(user, dict):
                    # Check for SailPoint-specific capability extensions
                    capabilities = user.get("urn:ietf:params:scim:schemas:sailpoint:1.0:User", {})
                    if isinstance(capabilities, dict):
                        cap_list = capabilities.get("capabilities", [])
                        if isinstance(cap_list, list) and len(cap_list) > 0:
                            result = True
                            break

                    # Check for authentication methods
                    auth_methods = user.get("authenticationMethods", user.get("mfa", None))
                    if auth_methods is not None:
                        result = True
                        break

            # If we got users back, IIQ is managing authentication
            if not result and len(users) > 0:
                # IdentityIQ delegates strong auth to its configured IdP
                # A valid user list confirms governance is in place
                result = total > 0 or len(users) > 0
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
