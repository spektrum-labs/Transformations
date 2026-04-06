import json
import ast


def transform(input):
    """
    Evaluates isIAMLoggingEnabled for Active Directory On-Prem (IAM)

    Checks: Whether AD audit logging is enabled for logon events and directory changes
    API Source: GET {baseURL}/api/policies/authentication
    Pass Condition: Audit policy settings indicate logging is enabled for account logon and directory service events
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

        # Check for audit logging indicators
        audit_enabled = data.get("auditLoggingEnabled", data.get("auditEnabled", False))
        logon_audit = data.get("logonAuditEnabled", data.get("accountLogonAudit", False))
        directory_audit = data.get("directoryServiceAudit", data.get("dsAuditEnabled", False))
        policies = data.get("auditPolicies", data.get("policies", []))

        if audit_enabled or (logon_audit and directory_audit):
            result = True
        elif isinstance(policies, list) and len(policies) > 0:
            # Check if any audit policies are active
            active_policies = [p for p in policies if p.get("enabled", p.get("isEnabled", False))]
            result = len(active_policies) > 0
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
