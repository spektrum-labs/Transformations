def transform(input):
    """
    Evaluates if the license has been purchased for Liongard.
    The environments list (and its count) shows only that the API key was accepted: Liongard's
    environments records carry no subscription or licence field. So only an explicit licence
    field in the body decides; an environments list, a count (0 included) or any other body is
    Not evaluated (None), and an error or explicit OFF is False.

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

        # An accepted API key, an environments list or a count (`count >= 0` was always true)
        # is not a licence. Only what the payload says about the licence decides.
        if isinstance(input, list):
            license_purchased = None if input else False
        else:
            license_purchased = affirmative_signal(input)

        if license_purchased is None:
            return {
                "transformedResponse": {"confirmedLicensePurchased": None},
                "additionalInfo": {"dataCollection": {"status": "error", "errors": [NOT_EVIDENCED_REASON]}},
            }

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


NOT_EVIDENCED_REASON = (
    "Not evaluated: the response carries no evidence for this criterion. A status field, an "
    "HTTP code or a list of records on its own only shows that the call succeeded."
)


def affirmative_signal(data):
    """What the payload says about this criterion: True, False, or None when it does not say.

    Replaces `data is not None`, which asked whether a response arrived rather than what
    it said -- so any 2xx body, including one describing the control as OFF, satisfied the
    criterion and no input could ever make it false. Measured 2026-09-21.

    A generic `status` or `state`, an HTTP code or a populated list shows only that the call
    succeeded, so it can veto but never assert. Measured 2026-11-17: this helper returned True
    for {"status": "ok"}, {"status": 200} and any non-empty list, including the stub the
    evaluation service substitutes for an empty or non-JSON 2xx body ({"status": "Success"}).

    In this order:
      * an unreadable, empty or error body                    -> False
      * an explicit OFF, in a setting key or in status/state  -> False   (beats any other signal)
      * an explicit ON in a setting key                       -> True
      * an empty collection                                   -> False
      * anything else                                         -> None    (Not evaluated)
    """
    if not isinstance(data, dict) or not data:
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault", "PSError"):
        if data.get(key):
            return False
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "enforced", "isEnforced", "loggingEnabled", "licensed", "licensePurchased",
               "subscribed", "subscription")
    present = [data[k] for k in on_keys if k in data]
    # `status` and `state` describe the call as often as the control: they may veto, never assert.
    reported = present + [data[k] for k in ("status", "state") if k in data]
    off_words = ("false", "disabled", "off", "inactive", "none", "expired", "cancelled")
    on_words = ("true", "enabled", "on", "active", "success", "ok", "valid", "licensed")
    for value in reported:
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
    for key in ("value", "items", "data", "records", "results", "logs", "events", "policies",
                "settings", "configurations", "devices", "agents", "users", "licenses"):
        value = data.get(key)
        if isinstance(value, (list, dict)) and not value:
            return False
    return None
