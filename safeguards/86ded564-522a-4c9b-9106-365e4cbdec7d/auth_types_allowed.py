def transform(input):
    """
    Returns False if any authenticator key includes 'email' or 'sms';
    True if an ACTIVE MFA_ENROLL policy exists and none are disallowed.
    """
    try:
        data = input.get('response', input)
        for p in data:
            if p.get('type') == 'MFA_ENROLL' and p.get('status') == 'ACTIVE':
                for a in p.get('settings', {}).get('authenticators', []):
                    key = a.get('key', '').lower()
                    if 'email' in key or 'sms' in key:
                        return {"authTypesAllowed": False}
                return {"authTypesAllowed": True}
        return {"authTypesAllowed": False}
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e)}
