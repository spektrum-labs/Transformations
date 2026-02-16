def transform(input):
    """
    Validates that password strength scores meet minimum thresholds in Keeper.

    Evaluates Commander security-audit-report for password strength metrics.
    Commander: security-audit-report

    Keeper scoring: Weak (<40), Fair (40-59), Medium (60-79), Strong (>=80)
    Threshold: Average score should be >= 60 (Medium or higher)

    NIST IA-5(1): Password-Based Authentication
    CIS Control 5.2: Use Unique Passwords (14+ chars for non-MFA, 8+ for MFA)

    Parameters:
        input (dict): The JSON data from Keeper Commander security-audit-report response

    Returns:
        dict: A dictionary with the isPasswordStrengthAdequate evaluation result
    """
    criteria_key = "isPasswordStrengthAdequate"

    # Keeper password strength thresholds
    STRENGTH_THRESHOLD = 60  # Medium or higher
    WEAK_THRESHOLD = 40
    FAIR_THRESHOLD = 60
    STRONG_THRESHOLD = 80

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

        strength_adequate = False
        strength_details = {
            "averageScore": 0,
            "totalRecords": 0,
            "weakPasswords": 0,
            "fairPasswords": 0,
            "mediumPasswords": 0,
            "strongPasswords": 0,
            "strengthThreshold": STRENGTH_THRESHOLD
        }

        # Check for security score
        security_score = input.get('security_score', input.get('securityScore',
                        input.get('average_score', input.get('averageScore', 0))))
        if security_score > 0:
            strength_details["averageScore"] = security_score
            strength_adequate = security_score >= STRENGTH_THRESHOLD

        # Check for password strength breakdown
        if 'password_strength' in input or 'passwordStrength' in input:
            ps = input.get('password_strength', input.get('passwordStrength', {}))
            if isinstance(ps, dict):
                strength_details["weakPasswords"] = ps.get('weak', ps.get('weak_count', 0))
                strength_details["fairPasswords"] = ps.get('fair', ps.get('fair_count', 0))
                strength_details["mediumPasswords"] = ps.get('medium', ps.get('medium_count', 0))
                strength_details["strongPasswords"] = ps.get('strong', ps.get('strong_count', 0))

                # Calculate average if provided
                avg = ps.get('average', ps.get('average_score', 0))
                if avg > 0:
                    strength_details["averageScore"] = avg
                    strength_adequate = avg >= STRENGTH_THRESHOLD

        # Check security audit data
        if 'security_audit' in input or 'securityAudit' in input:
            audit = input.get('security_audit', input.get('securityAudit', {}))
            if isinstance(audit, dict):
                # Get average score
                avg_score = audit.get('average_strength', audit.get('averageStrength',
                           audit.get('security_score', audit.get('securityScore', 0))))
                if avg_score > 0:
                    strength_details["averageScore"] = avg_score
                    strength_adequate = avg_score >= STRENGTH_THRESHOLD

                # Get weak password count
                weak = audit.get('weak_passwords', audit.get('weakPasswords', 0))
                strength_details["weakPasswords"] = weak

                # Get total records
                total = audit.get('total_records', audit.get('totalRecords', 0))
                strength_details["totalRecords"] = total

        # Check for individual user scores
        if 'users' in input:
            users = input['users']
            if isinstance(users, list):
                total_score = 0
                user_count = 0
                weak_count = 0
                fair_count = 0
                medium_count = 0
                strong_count = 0

                for user in users:
                    if isinstance(user, dict):
                        user_score = user.get('security_score', user.get('securityScore',
                                    user.get('password_strength', user.get('passwordStrength', 0))))
                        if user_score > 0:
                            total_score += user_score
                            user_count += 1

                            if user_score < WEAK_THRESHOLD:
                                weak_count += 1
                            elif user_score < FAIR_THRESHOLD:
                                fair_count += 1
                            elif user_score < STRONG_THRESHOLD:
                                medium_count += 1
                            else:
                                strong_count += 1

                if user_count > 0:
                    avg_score = total_score / user_count
                    strength_details["averageScore"] = round(avg_score, 2)
                    strength_adequate = avg_score >= STRENGTH_THRESHOLD
                    strength_details["weakPasswords"] = weak_count
                    strength_details["fairPasswords"] = fair_count
                    strength_details["mediumPasswords"] = medium_count
                    strength_details["strongPasswords"] = strong_count

        # Check Commander report format
        if 'report' in input:
            report = input['report']
            if isinstance(report, list):
                scores = []
                for entry in report:
                    if isinstance(entry, dict):
                        score = entry.get('score', entry.get('strength', entry.get('security_score', 0)))
                        if score > 0:
                            scores.append(score)
                            if score < WEAK_THRESHOLD:
                                strength_details["weakPasswords"] += 1
                            elif score < FAIR_THRESHOLD:
                                strength_details["fairPasswords"] += 1
                            elif score < STRONG_THRESHOLD:
                                strength_details["mediumPasswords"] += 1
                            else:
                                strength_details["strongPasswords"] += 1

                if scores:
                    avg_score = sum(scores) / len(scores)
                    strength_details["averageScore"] = round(avg_score, 2)
                    strength_details["totalRecords"] = len(scores)
                    strength_adequate = avg_score >= STRENGTH_THRESHOLD

        # Calculate compliance percentage
        total = (strength_details["weakPasswords"] + strength_details["fairPasswords"] +
                strength_details["mediumPasswords"] + strength_details["strongPasswords"])
        if total > 0:
            compliant = strength_details["mediumPasswords"] + strength_details["strongPasswords"]
            strength_details["compliancePercentage"] = round((compliant / total) * 100, 2)

        return {
            criteria_key: strength_adequate,
            **strength_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
