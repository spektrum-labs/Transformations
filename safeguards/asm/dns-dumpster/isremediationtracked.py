import json
import ast


def transform(input):
    """
    Evaluates isRemediationTracked for DNS Dumpster (ASM)

    Checks: Whether exposed subdomains and DNS records are tracked for changes
    API Source: https://api.dnsdumpster.com/domain/{domain}
    Pass Condition: Domain lookup returns records that can be monitored over time

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRemediationTracked": boolean, "trackedRecords": int, "domain": str}
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

        if not isinstance(dns_records, list):
            dns_records = []
        if not isinstance(mx_records, list):
            mx_records = []
        if not isinstance(ns_records, list):
            ns_records = []

        tracked_count = len(dns_records) + len(mx_records) + len(ns_records)
        domain = data.get("domain", "")

        result = tracked_count >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isRemediationTracked": result,
            "trackedRecords": tracked_count,
            "domain": domain
        }

    except Exception as e:
        return {"isRemediationTracked": False, "error": str(e)}
