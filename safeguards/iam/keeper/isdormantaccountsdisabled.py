def transform(input):
    """
    Validates that dormant accounts (inactive >45 days) are disabled in Keeper.

    Evaluates SCIM API response or Commander user-report for account activity.
    SCIM endpoint: GET /Users
    Commander: user-report

    CIS Control 5.3: Disable Dormant Accounts
    NIST AC-2(3): Disable Accounts

    Parameters:
        input (dict): The JSON data from Keeper SCIM /Users or Commander user-report response

    Returns:
        dict: A dictionary with the isDormantAccountsDisabled evaluation result
    """
    criteria_key = "isDormantAccountsDisabled"

    try:
        from datetime import datetime, timedelta

        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']
        if 'data' in input:
            input = input['data']

        dormant_disabled = True  # Assume compliant until we find violations
        dormant_details = {
            "totalUsers": 0,
            "activeUsers": 0,
            "dormantUsers": 0,
            "dormantEnabled": 0,  # Dormant but still enabled (violations)
            "dormantDisabled": 0,
            "dormancyThresholdDays": 45
        }

        # Define dormancy threshold (45 days per CIS Control 5.3)
        DORMANCY_THRESHOLD_DAYS = 45
        threshold_date = datetime.utcnow() - timedelta(days=DORMANCY_THRESHOLD_DAYS)

        def parse_date(date_str):
            """Parse various date formats."""
            if not date_str:
                return None
            formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d'
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            return None

        # Check SCIM Resources
        resources = input.get('Resources', input.get('resources', []))
        if isinstance(resources, list):
            dormant_details["totalUsers"] = len(resources)

            for user in resources:
                if isinstance(user, dict):
                    is_active = user.get('active', True)

                    # SCIM doesn't typically include last login, so we check active status
                    # If user is inactive, they're properly disabled
                    if not is_active:
                        dormant_details["dormantDisabled"] += 1
                    else:
                        dormant_details["activeUsers"] += 1

        # Check users array with activity data (Commander user-report format)
        users = input.get('users', [])
        if isinstance(users, list) and len(users) > 0:
            dormant_details["totalUsers"] = len(users)

            for user in users:
                if isinstance(user, dict):
                    # Get last activity/login timestamp
                    last_activity = user.get('last_login', user.get('lastLogin',
                                   user.get('last_activity', user.get('lastActivity'))))

                    is_active = user.get('active', user.get('status', 'active'))
                    is_enabled = is_active in [True, 'active', 'ACTIVE', 'enabled']

                    if last_activity:
                        activity_date = parse_date(last_activity)
                        if activity_date:
                            is_dormant = activity_date < threshold_date

                            if is_dormant:
                                dormant_details["dormantUsers"] += 1
                                if is_enabled:
                                    # Violation: dormant but still enabled
                                    dormant_details["dormantEnabled"] += 1
                                    dormant_disabled = False
                                else:
                                    dormant_details["dormantDisabled"] += 1
                            else:
                                dormant_details["activeUsers"] += 1
                        else:
                            # Can't parse date, assume active
                            dormant_details["activeUsers"] += 1
                    else:
                        # No activity data, check enabled status only
                        if is_enabled:
                            dormant_details["activeUsers"] += 1
                        else:
                            dormant_details["dormantDisabled"] += 1

        # Check for security audit data with dormant account info
        if 'security_audit' in input or 'securityAudit' in input:
            audit = input.get('security_audit', input.get('securityAudit', {}))
            if isinstance(audit, dict):
                dormant_count = audit.get('dormant_accounts', audit.get('dormantAccounts', 0))
                if dormant_count > 0:
                    dormant_details["dormantUsers"] = dormant_count
                    # If dormant accounts exist and are reported, check if any are enabled
                    dormant_enabled = audit.get('dormant_enabled', audit.get('dormantEnabled', 0))
                    if dormant_enabled > 0:
                        dormant_details["dormantEnabled"] = dormant_enabled
                        dormant_disabled = False

        # Check for inactive users list
        if 'inactive_users' in input or 'inactiveUsers' in input:
            inactive = input.get('inactive_users', input.get('inactiveUsers', []))
            if isinstance(inactive, list):
                for user in inactive:
                    if isinstance(user, dict):
                        if user.get('status', user.get('active', 'inactive')) in ['active', 'enabled', True]:
                            dormant_disabled = False
                            dormant_details["dormantEnabled"] += 1
                        else:
                            dormant_details["dormantDisabled"] += 1

        # Calculate compliance score
        total_dormant = dormant_details["dormantUsers"] or (dormant_details["dormantEnabled"] + dormant_details["dormantDisabled"])
        if total_dormant > 0:
            compliance_score = ((total_dormant - dormant_details["dormantEnabled"]) / total_dormant) * 100
            dormant_details["complianceScore"] = round(compliance_score, 2)

        return {
            criteria_key: dormant_disabled,
            **dormant_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
