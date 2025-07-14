def transform(input):
    """
    Returns True if strong auth is required for the given IDP
    """
    strongAuthRequired = False
    try:
        
        if isinstance(input, list):
            data = input
        elif isinstance(input, dict):
            data = input.get('response', input)

        for item in data:
            if item.get('status').lower() == 'active':
                strongAuthRequired = True

        return { "isStrongAuthRequired": strongAuthRequired }

    except Exception as e:
        return { "isStrongAuthRequired": False, "error": str(e) }
