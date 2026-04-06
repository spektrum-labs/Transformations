import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for StrongDM (IAM)

    Checks: Whether a valid StrongDM organization is active by confirming
            the organization endpoint returns a valid organization name.
    API Source: GET {baseURL}/v1/organization
    Pass Condition: API returns a valid response with a non-empty org name.
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

        # /v1/organization returns {"organization": {"name": "...", ...}}
        org = data.get("organization", data)
        if isinstance(org, dict):
            org_name = org.get("name", "")
        else:
            org_name = data.get("status", data.get("licensePurchased", ""))

        if isinstance(org_name, str) and len(org_name) > 0:
            result = True
        elif isinstance(org_name, bool):
            result = org_name

        # Check for any valid org-level info
        if not result:
            org_id = data.get("id", data.get("orgId", ""))
            if isinstance(org_id, str) and len(org_id) > 0:
                result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
