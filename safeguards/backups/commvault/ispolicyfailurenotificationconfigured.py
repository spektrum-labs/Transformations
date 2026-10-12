# ispolicyfailurenotificationconfigured.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getAlertNotifications (Integration-Service workflow)
#   1. listAlertDefinitions -> GET {serverUrl}/V4/AlertDefinitions
#   2. getAlertDefinition   -> GET {serverUrl}/V4/AlertDefinitions/{id}, once per definition (iterate alertDefinitions),
#                              under alertDefinitionDetails
# Docs:   https://github.com/Commvault/CVPowershellSDKV2/blob/main/OpenAPI3.yaml (Commvault's published V4 OpenAPI 3 spec)
#         GetAlertDefinitionsList: alertDefinitions[].id, enabled. GetAlertDefinitionsDetails: alertSummary.criteria.name
#         ("Backup Job Failed", "VM Backup failed", ...), associations, alertTarget.sendAlertTo (EMAIL, WEBHOOK, SNMP,
#         LIVEFEEDS, APPLOG, CONTENT_INDEX), alertTarget.recipients.to/cc/bcc, recipients.webHookId.
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    isPolicyFailureNotificationConfigured = true when an ENABLED alert definition with criteria "Backup Job
    Failed" or "VM Backup failed" is associated with at least one entity and notifies outside the console:
    EMAIL with a recipient, WEBHOOK with a webhook id, or SNMP. false otherwise, including a partial read
    (fewer detail bodies than definitions).
    """
    key = "isPolicyFailureNotificationConfigured"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("XML body; the method must send Accept: application/json")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        # Integration-Service may hand the body back under one of its envelopes.
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def vendor_error(d):
        """A reason string when the body is an Integration-Service or Commvault error, else None.
        Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        code = d.get("errorCode")
        if code not in (None, 0, "0"):
            return "Commvault error " + str(code) + ": " + str(d.get("errorMessage") or "")
        errs = d.get("errList")
        if isinstance(errs, list) and len(errs) > 0:
            return "Commvault errList: " + str(errs[0])[:200]
        err = d.get("error")
        if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
            return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")
        return None

    def as_int(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        return None

    try:
        data = unwrap(parse_input(input), "alertDefinitions")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        listed = data.get("alertDefinitions")
        if not isinstance(listed, list):
            return {key: False, "reason": "Response has no alertDefinitions list"}
        if len(listed) == 0:
            return {key: False, "reason": "No alert definitions exist"}
        details = data.get("alertDefinitionDetails")
        if isinstance(details, dict):
            details = [details]
        if not isinstance(details, list) or len(details) != len(listed):
            n = len(details) if isinstance(details, list) else 0
            return {key: False, "reason": "Read " + str(n) + " alert detail bodies for " + str(len(listed)) + " definitions"}
        enabled = {}
        for a in listed:
            if isinstance(a, dict):
                enabled[str(a.get("id"))] = a.get("enabled") is True
        wanted = ["backup job failed", "vm backup failed"]
        hits = []
        for b in details:
            b = unwrap(b, "alertSummary")
            if vendor_error(b) or not isinstance(b.get("alertSummary"), dict):
                return {key: False, "reason": "An alert detail body is unreadable"}
            crit = b["alertSummary"].get("criteria") if isinstance(b["alertSummary"].get("criteria"), dict) else {}
            if str(crit.get("name") or "").strip().lower() not in wanted:
                continue
            if not enabled.get(str(b.get("id"))):
                continue
            if not isinstance(b.get("associations"), list) or len(b.get("associations")) == 0:
                continue
            target = b.get("alertTarget") if isinstance(b.get("alertTarget"), dict) else {}
            channels = [str(x).upper() for x in (target.get("sendAlertTo") or [])]
            rec = target.get("recipients") if isinstance(target.get("recipients"), dict) else {}
            people = (rec.get("to") or []) + (rec.get("cc") or []) + (rec.get("bcc") or [])
            ok = ("EMAIL" in channels and len(people) > 0) or ("WEBHOOK" in channels and as_int(rec.get("webHookId"))) or ("SNMP" in channels)
            if ok:
                hits.append(str(b.get("name")) + " (" + ", ".join([c for c in channels if c in ("EMAIL", "WEBHOOK", "SNMP")]) + ")")
        if len(hits) == 0:
            return {key: False, "reason": "No enabled backup-failure alert notifies by email, webhook or SNMP (" + str(len(listed)) + " definitions read)"}
        return {key: True, "reason": str(len(hits)) + " enabled backup-failure alerts notify outside the console", "alerts": hits[:10]}
    except Exception as e:
        return {key: False, "error": str(e)}
