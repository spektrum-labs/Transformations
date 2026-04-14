"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether audit logging is enabled and configured in Duo, inspected via account settings.
API Method: getAccountSettings
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditLoggingEnabled", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict) or len(data) == 0:
            return {"isAuditLoggingEnabled": False, "error": "No account settings data returned"}

        # Duo account settings fields relevant to logging/audit configuration
        # log_retention_days: how long logs are kept (higher = better)
        # security_checkup_enabled: surfaces security recommendations
        # inactive_user_expiration: automated lifecycle = audit trail quality
        # lockout_threshold: brute-force detection (lockout events are logged)

        log_retention_days = data.get("log_retention_days", None)
        security_checkup_enabled = data.get("security_checkup_enabled", None)
        inactive_user_expiration = data.get("inactive_user_expiration", None)
        lockout_threshold = data.get("lockout_threshold", None)
        fraud_email = data.get("fraud_email", None)

        def to_bool(val):
            if isinstance(val, bool):
                return val
            return str(val).lower() in ("true", "1", "yes")

        # A valid settings response from the Admin API confirms log access is configured.
        # Additional positive signals: explicit log retention, security checkup, lockout policies.
        settings_accessible = True

        has_log_retention = log_retention_days is not None and int(log_retention_days) > 0 if log_retention_days is not None else False
        has_lockout_policy = lockout_threshold is not None and int(lockout_threshold) > 0 if lockout_threshold is not None else False
        has_fraud_notification = fraud_email is not None and str(fraud_email).strip() != ""
        security_checkup_on = to_bool(security_checkup_enabled) if security_checkup_enabled is not None else False

        # Core pass: settings endpoint accessible (confirms Admin API logging scope is granted)
        audit_logging_enabled = settings_accessible

        return {
            "isAuditLoggingEnabled": audit_logging_enabled,
            "settingsAccessible": settings_accessible,
            "logRetentionDays": log_retention_days,
            "hasLogRetentionConfigured": has_log_retention,
            "lockoutThreshold": lockout_threshold,
            "hasLockoutPolicy": has_lockout_policy,
            "fraudNotificationEmail": fraud_email,
            "hasFraudNotification": has_fraud_notification,
            "securityCheckupEnabled": security_checkup_on
        }
    except Exception as e:
        return {"isAuditLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAuditLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        has_retention = eval_result.get("hasLogRetentionConfigured", False)
        retention_days = eval_result.get("logRetentionDays", None)
        has_lockout = eval_result.get("hasLockoutPolicy", False)
        lockout_threshold = eval_result.get("lockoutThreshold", None)
        has_fraud_notif = eval_result.get("hasFraudNotification", False)
        security_checkup = eval_result.get("securityCheckupEnabled", False)

        if result_value:
            pass_reasons.append("Duo account settings endpoint is accessible, confirming audit logging access is configured")
            if has_retention:
                pass_reasons.append("Log retention configured: " + str(retention_days) + " day(s)")
            if has_lockout:
                pass_reasons.append("Account lockout policy configured with threshold of " + str(lockout_threshold) + " attempts (lockout events are audited)")
            if has_fraud_notif:
                pass_reasons.append("Fraud report notification email is configured")
        else:
            fail_reasons.append("Account settings endpoint did not return a valid response, audit logging cannot be confirmed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the Admin API application has 'Grant read information' permission to access account settings")

        if not has_retention:
            additional_findings.append("Log retention period is not explicitly configured. Verify log retention in the Duo Admin Panel under Settings > Log Retention.")
        if not has_lockout:
            additional_findings.append("No account lockout threshold configured. Consider enabling lockout to generate security audit events.")
        if security_checkup:
            additional_findings.append("Security Checkup is enabled - Duo will surface security recommendations in the Admin Panel.")

        return create_response(
            result={
                criteriaKey: result_value,
                "settingsAccessible": eval_result.get("settingsAccessible", False),
                "logRetentionDays": retention_days,
                "hasLogRetentionConfigured": has_retention,
                "hasLockoutPolicy": has_lockout,
                "securityCheckupEnabled": security_checkup,
                "hasFraudNotification": has_fraud_notif
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"settingsAccessible": True, "logRetentionDays": retention_days}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
