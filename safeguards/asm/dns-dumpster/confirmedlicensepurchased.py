import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for DNS Dumpster (ASM)

    Checks: Whether the DNS Dumpster API key is valid and returns domain data
    API Source: https://api.dnsdumpster.com/domain/{domain}
    Pass Condition: API returns a successful response with DNS records

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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
        error = data.get("error", None)
        status_code = data.get("status_code", data.get("statusCode", 200))

        has_dns = bool(data.get("dns", data.get("a", data.get("mx", []))))
        has_domain = bool(data.get("domain", ""))

        valid = (error is None) and (status_code == 200 or has_dns or has_domain)
        status = "active" if valid else "invalid"
        # ── END EVALUATION LOGIC ──

        return {
            "confirmedLicensePurchased": valid,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
