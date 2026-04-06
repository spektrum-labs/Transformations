import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for SailPoint IdentityNow (IAM)

    Checks: Whether a valid SailPoint IdentityNow tenant is active by
            confirming the org endpoint returns a valid organization name.
    API Source: GET {baseURL}/v3/org
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

        # /v3/org returns {"name": "tenant-name", "status": "...", ...}
        org_name = data.get("orgName", data.get("name", ""))
        status = data.get("status", "")
        license_purchased = data.get("licensePurchased", None)

        if isinstance(org_name, str) and len(org_name) > 0:
            result = True
        elif isinstance(license_purchased, bool):
            result = license_purchased
        elif isinstance(status, str) and len(status) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result, "orgName": str(org_name)}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
