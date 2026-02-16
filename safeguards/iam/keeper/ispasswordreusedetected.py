def transform(input):
    """
    Checks for password reuse across vault records in Keeper.

    Evaluates Commander security-audit-report for password reuse metrics.
    Commander: security-audit-report

    NIST IA-5(18): Password Managers - Prevent password reuse
    CIS Control 5.2: Use Unique Passwords

    Parameters:
        input (dict): The JSON data from Keeper Commander security-audit-report response

    Returns:
        dict: A dictionary with the isPasswordReuseDetected evaluation result
              NOTE: Returns True if reuse IS detected (indicating a problem)
    """
    criteria_key = "isPasswordReuseDetected"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']
        if 'data' in input:
            input = input['data']

        password_reuse_detected = False
        reuse_details = {
            "totalRecords": 0,
            "uniquePasswords": 0,
            "reusedPasswords": 0,
            "reusedPercentage": 0.0,
            "usersWithReuse": 0
        }

        # Check for reused passwords count
        reused_count = input.get('reused_passwords', input.get('reusedPasswords',
                      input.get('password_reuse_count', input.get('passwordReuseCount', 0))))
        if reused_count > 0:
            password_reuse_detected = True
            reuse_details["reusedPasswords"] = reused_count

        # Check for total/unique password metrics
        total_records = input.get('total_records', input.get('totalRecords',
                       input.get('record_count', input.get('recordCount', 0))))
        unique_passwords = input.get('unique_passwords', input.get('uniquePasswords', 0))

        reuse_details["totalRecords"] = total_records
        reuse_details["uniquePasswords"] = unique_passwords

        # Calculate reuse from total vs unique
        if total_records > 0 and unique_passwords > 0:
            if unique_passwords < total_records:
                password_reuse_detected = True
                reused = total_records - unique_passwords
                reuse_details["reusedPasswords"] = reused
                reuse_details["reusedPercentage"] = round((reused / total_records) * 100, 2)

        # Check security audit data
        if 'security_audit' in input or 'securityAudit' in input:
            audit = input.get('security_audit', input.get('securityAudit', {}))
            if isinstance(audit, dict):
                reused = audit.get('reused_passwords', audit.get('reusedPasswords', 0))
                if reused > 0:
                    password_reuse_detected = True
                    reuse_details["reusedPasswords"] = reused

                # Check password reuse data structure
                reuse_data = audit.get('password_reuse', audit.get('passwordReuse', {}))
                if isinstance(reuse_data, dict):
                    reuse_count = reuse_data.get('count', reuse_data.get('reused_count', 0))
                    if reuse_count > 0:
                        password_reuse_detected = True
                        reuse_details["reusedPasswords"] = reuse_count
                    reuse_details["reusedPercentage"] = reuse_data.get('percentage', 0)

        # Check for users with password reuse
        if 'users' in input:
            users = input['users']
            if isinstance(users, list):
                users_with_reuse = 0
                for user in users:
                    if isinstance(user, dict):
                        user_reuse = user.get('reused_passwords', user.get('reusedPasswords', 0))
                        if user_reuse > 0:
                            users_with_reuse += 1
                            password_reuse_detected = True
                reuse_details["usersWithReuse"] = users_with_reuse

        # Check for password health/quality data
        if 'password_health' in input or 'passwordHealth' in input:
            health = input.get('password_health', input.get('passwordHealth', {}))
            if isinstance(health, dict):
                reused = health.get('reused', health.get('duplicates', 0))
                if reused > 0:
                    password_reuse_detected = True
                    reuse_details["reusedPasswords"] = reused

        # Check Commander report format
        if 'report' in input:
            report = input['report']
            if isinstance(report, list):
                for entry in report:
                    if isinstance(entry, dict):
                        reuse_count = entry.get('reused', entry.get('reused_passwords', 0))
                        if reuse_count > 0:
                            password_reuse_detected = True
                            reuse_details["reusedPasswords"] += reuse_count

        return {
            criteria_key: password_reuse_detected,
            **reuse_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
