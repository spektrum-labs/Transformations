def transform(input):
    """
    Returns True if rbac is implemented for the given IDP
    """
    try:
        rbac = input.get('rbac') or []
        return {"isRBACImplemented": isinstance(rbac, list) and len(rbac) > 0}
    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}
