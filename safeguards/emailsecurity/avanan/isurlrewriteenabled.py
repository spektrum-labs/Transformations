"""
Transformation: isURLRewriteEnabled
Vendor: Avanan (Check Point Harmony Email & Collaboration), Smart API
Category: Email Security

NOT MEASURED. isURLRewriteEnabled returns
None with a dataCollection error, so it reads Unevaluated -- never Passed or Failed.

The Smart API publishes no URL-rewrite or click-time protection setting: its resources are
security events, SaaS entities, actions, tasks, exceptions and (for MSPs) tenants, licences
and users -- no policy or configuration endpoint. The only click-time evidence it carries is
per message: an email entity's entitySecurityResults.combinedVerdict.clicktimeProtection
(POST /v1.0/search/query). Reading that is a different method and a different transform;
safeguards/emailsecurity/checkpoint-harmony-email/isclicktimeurlrewriteenabled.py already
reads it for the Infinity Portal flavour of the same API, as isClickTimeURLRewriteEnabled.

The definition calls `getSecurityEvents`:
    POST {regionBaseURL}/v1.0/sec-events/search
That path is not in the vendor's published Smart API (SwaggerHub Check-Point/avanan-smart-api
1.40 and Check-Point/harmony-email-collaboration-smart-api 1.50, retrieved 2026-10-07), so there
is no documented response for this file to read.

What this file did before:
True whenever the body held a `securityEvents` (or `responseData`) list, empty or not --
"the events endpoint answered" reported as "URL rewriting is on" -- and from
`input.get('isURLRewriteEnabled')`, a field no Avanan API sends.
"""

from datetime import datetime

KEYS = ("isURLRewriteEnabled",)

REASON = ("Not measured: the Avanan Smart API publishes no URL-rewrite setting, and the "
          "definition's sec-events/search path is not in the published API")


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
                         "transformationId": "isURLRewriteEnabled", "vendor": "Avanan"}
        }
    }
