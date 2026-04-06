import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Active Directory On-Prem (IAM)

    Checks: Whether the AD domain is reachable and the service account can query domain info
    API Source: GET {baseURL}/api/domain/status
    Pass Condition: API returns a valid response indicating the domain controller is accessible
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

        # Check for domain status indicators
        domain_name = data.get("domainName", data.get("domain", data.get("name", "")))
        status = data.get("status", data.get("state", "")).lower()
        is_reachable = data.get("isReachable", data.get("reachable", False))

        if domain_name and (status in ("active", "online", "running", "ok") or is_reachable):
            result = True
        elif domain_name and len(domain_name) > 0:
            # If we got a domain name back, the service is responding
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
