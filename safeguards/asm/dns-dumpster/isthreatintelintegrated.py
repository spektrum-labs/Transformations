import json
import ast


def transform(input):
    """
    Evaluates isThreatIntelIntegrated for DNS Dumpster (ASM)

    Checks: Whether DNS records include ASN ownership and network block attribution
    API Source: https://api.dnsdumpster.com/domain/{domain}
    Pass Condition: At least one record has ASN or network owner information

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatIntelIntegrated": boolean, "hostsWithASN": int, "totalHosts": int}
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
        hosts_with_asn = [
            r for r in dns_records
            if r.get("asn") or r.get("as") or r.get("provider")
            or r.get("netblock") or r.get("country")
        ]

        result = total_hosts >= 1 and len(hosts_with_asn) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isThreatIntelIntegrated": result,
            "hostsWithASN": len(hosts_with_asn),
            "totalHosts": total_hosts
        }

    except Exception as e:
        return {"isThreatIntelIntegrated": False, "error": str(e)}
