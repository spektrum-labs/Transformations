"""
Transformation: isNetworkSecurityLoggingEnabled
Vendor: Cisco Meraki  |  Category: Network Security
Evaluates: Whether network security logging is active using multiple signals.

Data sources: Meraki Dashboard API v1
  - GET /organizations/{orgId}/appliance/security/events?perPage=3 (primary — security events flowing)
  - GET /networks/{networkId}/syslogServers (syslog forwarding configured)
  - GET /networks/{networkId}/alerts/settings (alert destinations configured)
  - GET /networks/{networkId}/snmp (SNMP monitoring configured)

Logging is considered enabled when ANY of these signals is positive:
  1. Security events are actively being generated (events array non-empty)
  2. Syslog servers are configured for log forwarding
  3. Alert settings have destinations configured with enabled alerts
  4. SNMP access is enabled (community or v3 users)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isNetworkSecurityLoggingEnabled", "vendor": "Cisco Meraki", "category": "Network Security"}
        }
    }


def check_security_events(data):
    """Check if security events are actively being generated.

    The org-level security events endpoint returns a list directly,
    or the workflow may place them as the primary response.
    """
    # Workflow primary response is from getNetworkSecurityEvents
    if isinstance(data, list) and len(data) > 0:
        # Check if items look like security events (have ts, eventType, etc.)
        first = data[0] if data else {}
        if isinstance(first, dict) and ("ts" in first or "eventType" in first):
            return True, len(data)
        return True, len(data)

    # Nested in events key
    events = data.get("events", [])
    if isinstance(events, list) and len(events) > 0:
        return True, len(events)

    return False, 0


def check_syslog(data):
    """Check if syslog servers are configured."""
    syslog_data = data.get("syslogServers", data)
    if isinstance(syslog_data, dict):
        servers = syslog_data.get("servers", [])
    elif isinstance(syslog_data, list):
        servers = syslog_data
    else:
        servers = []

    configured = [s for s in servers if isinstance(s, dict)]

    # Check for security-relevant syslog roles
    security_roles = {"IDS alerts", "Security events", "Appliance event log", "Air Marshal events", "Flows"}
    security_servers = []
    for server in configured:
        roles = server.get("roles", [])
        if isinstance(roles, list) and security_roles.intersection(set(roles)):
            security_servers.append(server.get("host", "unknown"))

    return len(configured) > 0, len(configured), security_servers


def check_alerts(data):
    """Check if alert settings have destinations and enabled alerts."""
    alert_data = data.get("alertSettings", {})
    if not isinstance(alert_data, dict):
        return False, 0

    defaults = alert_data.get("defaultDestinations", {})
    has_default_dest = False
    if isinstance(defaults, dict):
        has_emails = bool(defaults.get("emails"))
        has_all_admins = bool(defaults.get("allAdmins"))
        has_http = bool(defaults.get("httpServerIds"))
        has_snmp = bool(defaults.get("snmp"))
        has_default_dest = has_emails or has_all_admins or has_http or has_snmp

    alerts = alert_data.get("alerts", [])
    enabled_alerts = 0
    if isinstance(alerts, list):
        for alert in alerts:
            if isinstance(alert, dict) and alert.get("enabled"):
                enabled_alerts += 1

    return has_default_dest and enabled_alerts > 0, enabled_alerts


def check_snmp(data):
    """Check if SNMP monitoring is enabled."""
    snmp_data = data.get("snmpSettings", {})
    if not isinstance(snmp_data, dict):
        return False, "none"
    access = snmp_data.get("access", "none")
    return access != "none", access


def evaluate(data):
    """Evaluate network security logging via multiple signals."""
    try:
        events_active, event_count = check_security_events(data)
        syslog_configured, syslog_count, security_syslog_hosts = check_syslog(data)
        alerts_configured, enabled_alert_count = check_alerts(data)
        snmp_enabled, snmp_access = check_snmp(data)

        signals_passing = []
        signals_failing = []

        if events_active:
            signals_passing.append(f"Security event logging active ({event_count} recent events)")
        else:
            signals_failing.append("No recent security events found")

        if syslog_configured:
            msg = f"Syslog forwarding configured ({syslog_count} server(s))"
            if security_syslog_hosts:
                msg += f" — security roles on: {', '.join(security_syslog_hosts[:5])}"
            signals_passing.append(msg)
        else:
            signals_failing.append("No syslog servers configured")

        if alerts_configured:
            signals_passing.append(f"Alert destinations configured ({enabled_alert_count} enabled alerts)")
        else:
            signals_failing.append("No alert destinations with enabled alerts")

        if snmp_enabled:
            signals_passing.append(f"SNMP monitoring enabled (access: {snmp_access})")
        else:
            signals_failing.append("SNMP access disabled")

        logging_enabled = len(signals_passing) > 0

        return {
            "isNetworkSecurityLoggingEnabled": logging_enabled,
            "securityEventsActive": events_active,
            "syslogConfigured": syslog_configured,
            "syslogSecurityRolesConfigured": len(security_syslog_hosts) > 0,
            "alertsConfigured": alerts_configured,
            "snmpEnabled": snmp_enabled,
            "signalsPassing": len(signals_passing),
            "signalsTotal": len(signals_passing) + len(signals_failing),
            "findings": signals_passing + signals_failing
        }
    except Exception as e:
        return {"isNetworkSecurityLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isNetworkSecurityLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            passing = eval_result.get("signalsPassing", 0)
            total = eval_result.get("signalsTotal", 0)
            pass_reasons.append(f"{passing}/{total} logging signals active")
            if eval_result.get("securityEventsActive"):
                pass_reasons.append("Security events are actively being recorded")
            if eval_result.get("syslogConfigured"):
                pass_reasons.append("Syslog forwarding is configured")
                if eval_result.get("syslogSecurityRolesConfigured"):
                    pass_reasons.append("Syslog servers have security-relevant roles assigned (IDS alerts, Security events, etc.)")
            if eval_result.get("alertsConfigured"):
                pass_reasons.append("Alert notifications are configured")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            fail_reasons.append("No logging signals detected across security events, syslog, alerts, or SNMP")
            recommendations.append("Configure syslog servers with security event roles (IDS alerts, Security events, Appliance event log)")
            recommendations.append("Enable alert destinations and security-related alerts in the Meraki Dashboard")
            recommendations.append("If using an external SIEM via Cisco FMC, verify logging is enabled on the FMC firewall integration instead")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "signalsPassing": extra_fields.get("signalsPassing", 0), "signalsTotal": extra_fields.get("signalsTotal", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
