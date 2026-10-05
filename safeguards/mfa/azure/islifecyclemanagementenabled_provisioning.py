"""
Transformation: isLifeCycleManagementEnabled (Azure AD One-Click, Entra provisioning logs)
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management

Criterion: "Lifecycle management enabled" -- leavers lose access automatically. Read here as: in the last
30 days the Microsoft Entra provisioning service itself (not an administrator) successfully disabled or
deleted at least one user account. That covers the three automatic routes Entra has:
  * HR-driven inbound provisioning (Workday, SAP SuccessFactors, API-driven) disabling the Entra user
    when the worker leaves,
  * outbound app provisioning (SCIM / gallery connectors) disabling or deleting the downstream account
    when the Entra user is disabled, deleted or unassigned,
  * Entra Connect cloud sync carrying an on-premises disable or delete into Entra ID.
An event is proof the automation exists and runs. A configuration flag alone is not, and GET /v1.0/users
(the old mapping, any tenant with users passed) says nothing about provisioning or deprovisioning.

Data source: IS method getProvisioningDeprovisionEvents on Azure AD (One-Click) cde89168:
  GET https://graph.microsoft.com/v1.0/auditLogs/provisioning
      ?$filter=provisioningAction eq 'disable' or provisioningAction eq 'delete'   (server-side narrowing;
      the transform classifies every record itself, so an unfiltered read gives the same verdict)
  https://learn.microsoft.com/en-us/graph/api/provisioningobjectsummary-list
  Application permissions AuditLog.Read.All and Directory.Read.All (both already in the One-Click consent).
  Paged by IS on @odata.nextLink (pagination type "link", dataPath "value"); IS merges pages into `value`.
Input: {"@odata.context": ..., "value": [provisioningObjectSummary, ...]} (may also arrive wrapped).

A record counts as an automatic leaver deprovisioning only when ALL hold:
  provisioningAction      "disable" or "delete"
  provisioningStatusInfo  status "success" (the deprecated statusInfo is read when the new one is absent)
  initiatedBy             initiatorType (Graph also documents "initiatingType") "system" or "application";
                          "user" is an admin's on-demand provisioning, which is manual, and absent is unknown
  identity                targetIdentity or sourceIdentity identityType names a user or worker (groups,
                          service principals and role objects are not leavers)
  activityDateTime        readable and within the last 30 days (Entra keeps provisioning logs 30 days)

Verdict:
  True   complete read, at least one qualifying event.
  False  complete read and no qualifying event: no provisioning activity at all, or only creates/updates,
         failed/skipped deprovisioning, on-demand runs by an admin, group objects or stale events.
  None   (Unevaluated, dataCollection error) no Graph envelope, a Graph error body (403 without consent or
         a non-premium tenant, 401, throttling), no `value` list, a non-object record, or a partial read:
         @odata.nextLink still present or an IS truncated marker (IS stopped at maxPages or a page failed).
         Nothing is reported satisfied from a body that was not read in full.
"""
import json
from datetime import datetime

KEY = "isLifeCycleManagementEnabled"
WINDOW_DAYS = 30
DEPROVISION_ACTIONS = ["disable", "delete"]
AUTOMATIC_INITIATORS = ["system", "application"]


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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": "isLifeCycleManagementEnabled_provisioning",
                         "vendor": "Microsoft", "category": "Identity"},
        },
    }


def unevaluated(problem, validation=None, summary=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem],
                           api_errors=[problem], input_summary=summary)


def is_partial(feed):
    if feed.get("@odata.nextLink"):
        return True
    if feed.get("truncated") is True:
        return True
    for key in ["pagination", "@odata"]:
        block = feed.get(key)
        if isinstance(block, dict) and block.get("truncated") is True:
            return True
    return False


def read_feed(data):
    """(records, problem) for the provisioning-log collection."""
    if not isinstance(data, dict) or not data:
        return None, "No Microsoft Graph provisioning-log envelope in the response; nothing to evaluate."
    err = data.get("error") or data.get("errors")
    if err:
        code = ""
        if isinstance(err, dict):
            code = str(err.get("code") or err.get("message") or "")
        return None, ("Microsoft Graph returned an error for /auditLogs/provisioning" +
                      (" (" + code[:120] + ")" if code else "") +
                      "; the tenant may not have consented to AuditLog.Read.All or lacks an Entra ID premium licence.")
    status = data.get("statusCode") or data.get("status_code")
    if isinstance(status, int) and status >= 400:
        return None, "The provisioning-log read failed with HTTP " + str(status) + "; nothing was read."
    records = data.get("value")
    if not isinstance(records, list):
        return None, "The response is not a Graph provisioning-log collection (no value list)."
    if is_partial(data):
        return None, ("Read " + str(len(records)) + " provisioning event(s) but more pages remain "
                      "(@odata.nextLink or truncated marker present); a partial read is not evaluated.")
    for r in records:
        if not isinstance(r, dict):
            return None, "A provisioning-log record is not an object."
    return records, None


def lower_text(value):
    if isinstance(value, str):
        return value.strip().lower()
    return ""


def parse_graph_time(value):
    """'2026-09-28T14:03:11Z' / '2026-09-28T14:03:11.1234567Z' -> naive UTC datetime, or None."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    text = value[:19]
    if text[4] != "-" or text[7] != "-" or text[10] not in ["T", " "] or text[13] != ":" or text[16] != ":":
        return None
    try:
        return datetime(int(text[0:4]), int(text[5:7]), int(text[8:10]),
                        int(text[11:13]), int(text[14:16]), int(text[17:19]))
    except Exception:
        return None


def status_of(record):
    info = record.get("provisioningStatusInfo")
    if not isinstance(info, dict):
        info = record.get("statusInfo")
    if isinstance(info, dict):
        return lower_text(info.get("status"))
    return ""


def initiator_of(record):
    by = record.get("initiatedBy")
    if not isinstance(by, dict):
        return ""
    return lower_text(by.get("initiatorType") or by.get("initiatingType"))


def is_person(record):
    for side in ["targetIdentity", "sourceIdentity"]:
        ident = record.get(side)
        if isinstance(ident, dict):
            t = lower_text(ident.get("identityType"))
            if "group" in t:
                return False
            if "user" in t or t == "worker":
                return True
    return False


def app_name(record):
    sp = record.get("servicePrincipal")
    # Tenant-admin-controlled text that is echoed into reasons: length-capped.
    if isinstance(sp, dict) and isinstance(sp.get("displayName"), str) and sp.get("displayName").strip():
        return sp.get("displayName").strip()[:80]
    return "unnamed provisioning app"


def classify(record, now):
    """'qualifying' or the reason the record does not count."""
    if lower_text(record.get("provisioningAction")) not in DEPROVISION_ACTIONS:
        return "notDeprovisioning"
    if status_of(record) != "success":
        return "notSuccessful"
    if initiator_of(record) not in AUTOMATIC_INITIATORS:
        return "notAutomatic"
    if not is_person(record):
        return "notUser"
    when = parse_graph_time(record.get("activityDateTime"))
    if when is None:
        return "noTimestamp"
    age_days = (now - when).total_seconds() / 86400.0
    if age_days > WINDOW_DAYS or age_days < -1:
        return "outsideWindow"
    return "qualifying"


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if isinstance(validation, dict) and validation.get("status") == "failed":
            return unevaluated("Input validation failed; nothing to evaluate.", validation)

        records, problem = read_feed(data)
        if problem:
            return unevaluated(problem, validation)

        now = datetime.utcnow()
        counts = {"qualifying": 0, "notDeprovisioning": 0, "notSuccessful": 0, "notAutomatic": 0,
                  "notUser": 0, "noTimestamp": 0, "outsideWindow": 0}
        apps = []
        for r in records:
            verdict = classify(r, now)
            counts[verdict] = counts[verdict] + 1
            if verdict == "qualifying":
                name = app_name(r)
                if name not in apps:
                    apps.append(name)

        summary = {"eventsRead": len(records), "windowDays": WINDOW_DAYS,
                   "automaticUserDeprovisionings": counts["qualifying"],
                   "deprovisioningApps": apps[:10],
                   "excluded": {k: counts[k] for k in counts if k != "qualifying"}}
        result = {KEY: counts["qualifying"] > 0, "automaticUserDeprovisionings": counts["qualifying"],
                  "provisioningEventsRead": len(records)}

        if counts["qualifying"] > 0:
            return create_response(
                result=result, validation=validation,
                pass_reasons=["The Entra provisioning service automatically disabled or deleted " +
                              str(counts["qualifying"]) + " user account(s) in the last " + str(WINDOW_DAYS) +
                              " days via: " + ", ".join(apps[:10])],
                input_summary=summary)

        if not records:
            reason = ("No provisioning-service disable or delete events in the last " + str(WINDOW_DAYS) +
                      " days: no automatic deprovisioning is evidenced for this tenant.")
        elif counts["notSuccessful"] > 0:
            reason = (str(counts["notSuccessful"]) + " deprovisioning attempt(s) did not succeed and none "
                      "succeeded automatically in the last " + str(WINDOW_DAYS) + " days.")
        else:
            reason = ("None of the " + str(len(records)) + " provisioning event(s) is a successful automatic "
                      "disable or delete of a user in the last " + str(WINDOW_DAYS) + " days.")
        return create_response(
            result=result, validation=validation,
            fail_reasons=[reason],
            recommendations=["Configure automatic deprovisioning: HR-driven inbound provisioning or Lifecycle "
                             "Workflows for leavers, and SCIM provisioning for connected apps so disabled or "
                             "unassigned users are removed downstream"],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
