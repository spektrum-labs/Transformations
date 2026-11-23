"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Avanan (Check Point Harmony Email & Collaboration), Smart API
Category: Email Security

NOT MEASURED. isEmailSecurityLoggingEnabled and isEmailLoggingEnabled return
None with a dataCollection error, so each reads Unevaluated -- never Passed or Failed.

The Smart API publishes no audit-log resource and no logging setting; security-event
retention is a property of the platform, not something a customer configures through it. What
it does publish is the event log itself (POST /v1.0/event/query: eventId, type, eventCreated,
actions). safeguards/emailsecurity/checkpoint-harmony-email/isemailsecurityloggingenabled.py
already reads that body, against a captured response, for the Infinity Portal flavour of the
same API.

The definition calls `getAuditLogs`:
    GET {regionBaseURL}/v1.0/audit/logs
That path is not in the vendor's published Smart API (SwaggerHub Check-Point/avanan-smart-api
1.40 and Check-Point/harmony-email-collaboration-smart-api 1.50, retrieved 2026-10-07), so there
is no documented response for this file to read.

What this file did before:
True when the body held a non-empty `auditLogs`/`responseData`/`securityEvents` list or
affirmative_signal liked it, and from `input.get('isEmailSecurityLoggingEnabled')`, a field
no Avanan API sends.
"""

from datetime import datetime

KEYS = ("isEmailSecurityLoggingEnabled", "isEmailLoggingEnabled")

REASON = ("Not measured: the Avanan Smart API publishes no audit-log resource or logging "
          "setting, and the definition's audit/logs path is not in the published API")


def transform(input):
    # No body can change this answer, so the body is not read: a value that is always None
    # carries its error status with it, on every path including a body whose reads raise.
    result = {}
    for key in KEYS:
        result[key] = None
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [REASON]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [REASON], "recommendations": [],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isEmailSecurityLoggingEnabled", "vendor": "Avanan"}
        }
    }
