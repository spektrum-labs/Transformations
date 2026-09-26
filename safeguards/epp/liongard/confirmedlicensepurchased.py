def transform(input):
    """
    Evaluates if the license has been purchased for Liongard.
    Checks the environments API response to verify valid API key/subscription.

    Parameters:
        input (dict): The JSON data containing Liongard API environments response.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
        # The production executor passes this transform the ENRICHED envelope
        # {"data": <body>, "validation": {...}}, because it classifies any source that reads
        # `input.get('data'` as new-format. Unwrap it first: otherwise the envelope's own
        # non-empty `data` key reads as evidence, and any non-empty body -- an auth error,
        # an unrelated payload -- reports the license purchased.
        if isinstance(input, dict) and 'data' in input and 'validation' in input:
            input = input['data']

        # Handle nested response structure
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        # If we got a valid response from the environments endpoint,
        # it means the API key is valid and the subscription is active
        # `input is not None` asked whether a RESPONSE ARRIVED, not what it said, so any
        # 2xx body -- including one describing the control as OFF -- satisfied this
        # criterion and no input could make it false. Resolved from the payload now.
        default_value = affirmative_signal(input)

        # Check if environments were returned (indicates valid subscription)
        has_data = False
        if isinstance(input, dict):
            # Check for data array or environments list
            data = input.get('data', input.get('environments', input.get('items', [])))
            has_data = len(data) > 0 if isinstance(data, list) else bool(data)
            # Also check for count field
            if not has_data and 'count' in input:
                has_data = int(input.get('count', 0)) >= 0
        elif isinstance(input, list):
            has_data = len(input) > 0

        license_purchased = has_data or default_value

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def affirmative_signal(data):
    """True only when the payload POSITIVELY evidences the control.

    Replaces `data is not None`, which asked whether a response arrived rather than what
    it said -- so any 2xx body, including one describing the control as OFF, satisfied the
    criterion and no input could ever make it false. Measured 2026-09-21.

    Deliberately conservative, in this order:
      * an unreadable, empty or error body           -> False
      * an explicit OFF among the recognised keys    -> False   (beats any other signal)
      * an explicit ON among the recognised keys     -> True
      * a non-empty population of records/settings   -> True
      * anything unrecognised                        -> False  (never True by default)
    """
    if not isinstance(data, dict) or not data:
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault", "PSError"):
        if data.get(key):
            return False
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "enforced", "isEnforced", "loggingEnabled", "status", "state", "licensed",
               "licensePurchased", "subscribed", "subscription")
    present = [data[k] for k in on_keys if k in data]
    off_words = ("false", "disabled", "off", "inactive", "none", "expired", "cancelled")
    on_words = ("true", "enabled", "on", "active", "success", "ok", "valid", "licensed")
    for value in present:
        if value is False:
            return False
        if isinstance(value, str) and value.strip().lower() in off_words:
            return False
    for value in present:
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in on_words:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return True
    for key in ("items", "data", "records", "results", "logs", "events", "policies",
                "settings", "configurations", "devices", "agents", "users", "licenses"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    return False
