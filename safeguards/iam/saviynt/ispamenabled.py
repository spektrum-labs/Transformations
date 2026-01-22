def transform(input):
    """
    Validate privileged accounts are managed

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the isPAMEnabled evaluation result
    """

    criteria_key = "isPAMEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        pam_enabled = False
        pam_details = {}

        # Check for privilegedAccounts array (Saviynt getPrivilegedAccounts response)
        if 'privilegedAccounts' in input:
            accounts = input['privilegedAccounts']
            if isinstance(accounts, list):
                pam_enabled = len(accounts) > 0
                pam_details['privilegedAccountCount'] = len(accounts)
        elif 'accounts' in input:
            accounts = input['accounts']
            if isinstance(accounts, list):
                # Check for privileged flags in accounts
                privileged = [a for a in accounts if
                    a.get('privileged', False) or
                    a.get('customproperty1', '').lower() == 'privileged' or
                    'admin' in str(a.get('accountname', '')).lower() or
                    'privileged' in str(a).lower()
                ]
                pam_enabled = len(privileged) > 0 or len(accounts) > 0
                pam_details['totalAccounts'] = len(accounts)
                pam_details['privilegedAccounts'] = len(privileged)
        elif 'totalcount' in input and input.get('totalcount', 0) > 0:
            pam_enabled = True
            pam_details['totalPrivilegedAccounts'] = input['totalcount']
        elif 'pamEnabled' in input:
            pam_enabled = bool(input['pamEnabled'])

        return {
            criteria_key: pam_enabled,
            **pam_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
