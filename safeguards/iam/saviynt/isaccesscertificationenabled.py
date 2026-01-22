def transform(input):
    """
    Check access certifications are configured

    Parameters:
        input (dict): The JSON data containing Saviynt API response

    Returns:
        dict: A dictionary with the isAccessCertificationEnabled evaluation result
    """

    criteria_key = "isAccessCertificationEnabled"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        certification_enabled = False
        certification_details = {}

        # Check for certifications array (Saviynt fetchCertifications response)
        if 'certifications' in input:
            certs = input['certifications']
            if isinstance(certs, list):
                # Check for active certifications
                active_certs = [c for c in certs if
                    c.get('status', '').lower() in ['active', 'in progress', 'pending', 'scheduled'] or
                    c.get('certificationstatus', '').lower() in ['active', 'in progress', 'pending', 'scheduled']
                ]
                if len(active_certs) == 0 and len(certs) > 0:
                    # If no status filtering matches, assume certifications exist
                    active_certs = certs
                certification_enabled = len(active_certs) > 0
                certification_details['totalCertifications'] = len(certs)
                certification_details['activeCertifications'] = len(active_certs)
        elif 'totalcount' in input and input.get('totalcount', 0) > 0:
            certification_enabled = True
            certification_details['totalCertifications'] = input['totalcount']
        elif 'certificationEnabled' in input:
            certification_enabled = bool(input['certificationEnabled'])

        return {
            criteria_key: certification_enabled,
            **certification_details
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
