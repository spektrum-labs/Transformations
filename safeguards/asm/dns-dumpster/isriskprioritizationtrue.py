import json
import ast


def transform(input):
    """
    Evaluates isRiskPrioritizationTrue for DNS Dumpster (ASM)

    Checks: Whether discovered hosts include banner data and open port exposure
    API Source: https://api.dnsdumpster.com/domain/{domain}
    Pass Condition: At least one host has banner or port information for risk assessment

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRiskPrioritizationTrue": boolean, "hostsWithBanners": int, "totalHosts": int}
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
        dns_records = data.get("dns", data.get("a", []))

        if not isinstance(dns_records, list):
            dns_records = []

        total_hosts = len(dns_records)
        hosts_with_banners = [
            r for r in dns_records
            if r.get("banners") or r.get("ports") or r.get("open_ports")
            or r.get("header") or r.get("technologies")
        ]

        result = total_hosts >= 1 and len(hosts_with_banners) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isRiskPrioritizationTrue": result,
            "hostsWithBanners": len(hosts_with_banners),
            "totalHosts": total_hosts
        }

    except Exception as e:
        return {"isRiskPrioritizationTrue": False, "error": str(e)}
