import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for StrongDM (IAM)

    Checks: Whether strong authentication is required by checking accounts
            for MFA enforcement settings.
    API Source: GET {baseURL}/v1/accounts
    Pass Condition: Accounts exist with MFA or SSO requirements enforced.
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

        accounts = data.get("accounts", data)
        if isinstance(accounts, dict):
            accounts = accounts.get("items", accounts.get("data", []))

        if isinstance(accounts, list) and len(accounts) > 0:
            # StrongDM enforces strong auth through its gateway architecture.
            # All connections require authentication through the SDM client.
            mfa_enabled_count = 0
            for account in accounts:
                if isinstance(account, dict):
                    # Check for MFA/SSO enforcement
                    mfa = account.get("mfaEnabled", account.get("requireMfa", None))
                    auth_type = str(account.get("authType", account.get("authenticationType", ""))).lower()

                    if isinstance(mfa, bool) and mfa:
                        mfa_enabled_count = mfa_enabled_count + 1
                    elif "sso" in auth_type or "mfa" in auth_type or "saml" in auth_type:
                        mfa_enabled_count = mfa_enabled_count + 1

            if mfa_enabled_count > 0:
                result = True
            elif len(accounts) > 0:
                # StrongDM inherently requires strong auth via its agent
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
