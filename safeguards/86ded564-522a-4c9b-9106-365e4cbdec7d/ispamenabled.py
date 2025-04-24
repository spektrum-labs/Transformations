def transform(input):
    """
    Returns True if privilegedAccounts or pamPolicies is non‑empty.
    """
    try:
        pam = input.get('privilegedAccounts') or input.get('pamPolicies') or []
        return {"isPAMEnabled": isinstance(pam, list) and len(pam) > 0}
    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}
