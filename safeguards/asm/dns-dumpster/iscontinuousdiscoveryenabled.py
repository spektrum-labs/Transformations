import json
import ast


def transform(input):
    """
    Evaluates isContinuousDiscoveryEnabled for DNS Dumpster (ASM)

    Checks: Whether DNS record enumeration returns subdomains and host records
    API Source: https://api.dnsdumpster.com/domain/{domain}
    Pass Condition: Response contains at least one DNS A record or subdomain

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousDiscoveryEnabled": boolean, "subdomainCount": int, "recordTypes": list}
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
        mx_records = data.get("mx", [])
        ns_records = data.get("ns", [])
        txt_records = data.get("txt", [])

        if not isinstance(dns_records, list):
            dns_records = []

        subdomain_count = len(dns_records)
        record_types = []
        if dns_records:
            record_types.append("A")
        if mx_records:
            record_types.append("MX")
        if ns_records:
            record_types.append("NS")
        if txt_records:
            record_types.append("TXT")

        result = subdomain_count >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isContinuousDiscoveryEnabled": result,
            "subdomainCount": subdomain_count,
            "recordTypes": record_types
        }

    except Exception as e:
        return {"isContinuousDiscoveryEnabled": False, "error": str(e)}
