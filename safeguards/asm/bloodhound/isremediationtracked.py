import json
import ast


def transform(input):
    """
    Evaluates isRemediationTracked for BloodHound Enterprise (ASM)

    Checks: Whether domain findings show remediation progress over time
    API Source: {baseURL}/api/v2/domains
    Pass Condition: Domains contain collected data with posture tracking fields

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRemediationTracked": boolean, "domainsTracked": int, "totalDomains": int}
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
        domains = data.get("data", data.get("domains", data.get("results", [])))

        if isinstance(domains, dict):
            domains = domains.get("domains", [])

        if not isinstance(domains, list):
            return {
                "isRemediationTracked": False,
                "domainsTracked": 0,
                "totalDomains": 0,
                "error": "Unexpected domains response format"
            }

        total = len(domains)
        tracked = [
            d for d in domains
            if d.get("collected", False)
            or d.get("last_collected") is not None
            or d.get("analysis_completed") is not None
        ]

        result = total >= 1 and len(tracked) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isRemediationTracked": result,
            "domainsTracked": len(tracked),
            "totalDomains": total
        }

    except Exception as e:
        return {"isRemediationTracked": False, "error": str(e)}
