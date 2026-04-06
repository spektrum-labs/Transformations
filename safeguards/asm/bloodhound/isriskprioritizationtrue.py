import json
import ast


def transform(input):
    """
    Evaluates isRiskPrioritizationTrue for BloodHound Enterprise (ASM)

    Checks: Whether attack path findings include severity or risk-based prioritization
    API Source: {baseURL}/api/v2/domains
    Pass Condition: Domain data includes tier-zero asset exposure metrics or risk scores

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRiskPrioritizationTrue": boolean, "domainCount": int, "domainsWithRisk": int}
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
                "isRiskPrioritizationTrue": False,
                "domainCount": 0,
                "domainsWithRisk": 0,
                "error": "Unexpected domains response format"
            }

        domain_count = len(domains)
        domains_with_risk = [
            d for d in domains
            if d.get("impact_value") is not None
            or d.get("exposure") is not None
            or d.get("risk_score") is not None
            or d.get("tier_zero_count", 0) > 0
        ]

        result = domain_count >= 1 and len(domains_with_risk) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isRiskPrioritizationTrue": result,
            "domainCount": domain_count,
            "domainsWithRisk": len(domains_with_risk)
        }

    except Exception as e:
        return {"isRiskPrioritizationTrue": False, "error": str(e)}
