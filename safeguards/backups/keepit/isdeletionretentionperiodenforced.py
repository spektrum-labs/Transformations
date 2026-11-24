# isdeletionretentionperiodenforced.py - Keepit
#
# Method: getRetentionConfig (Integration-Service workflow, results merged into one object)
#   1. listDevices  -> GET {serverUrl}/users/{accountId}/devices   (per-connector <backup-retention>)
#   2. getResources -> GET {serverUrl}/users/{accountId}/resources (product retention resources)
# Docs:   https://developers.keepit.com/api/data-protection/connectors#list-devices
#           schema "devices": cloud/backup-retention "Device-specific backup retention period"
#         https://developers.keepit.com/api/products/resources#list-resources
#           schema "user-resources": resource/name, resource/limit
#         https://developers.keepit.com/resource-names
#           generic-snapshot-retention and <type>-snapshot-retention, "Keep snapshots ... no
#           more than this period"; delete-retention-period, "Period during which deleted
#           device/user can be recovered". A live body states these as a resource with
#           type "period" and a limit that is an ISO 8601 duration, for example
#           {"name": "delete-retention-period", "type": "period", "limit": "P1M"}.
#
# Two periods answer this check, and the shortest stated one decides:
#   * delete-retention-period: how long a deleted connector or user stays recoverable. It is one
#     account-wide resource, so it covers every connector.
#   * snapshot retention: how long a snapshot (and so an item deleted at the source) is kept,
#     per connector. An item deleted at the source stays recoverable for as long as a snapshot
#     that holds it is kept.

import json
import re
from datetime import datetime, timezone

KEY = "isDeletionRetentionPeriodEnforced"
METHOD = "getRetentionConfig"


def transform_bare(input):
    """
    True when the retention Keepit states is at least one month (30 days), so a deleted
    connector, user or item stays recoverable for at least that long.

    Two periods are read, each as an ISO 8601 duration (a month is 30 days, a year 365):
    the account's delete-retention-period resource (how long a deleted connector or user stays
    recoverable) and each cloud connector's effective snapshot retention. The shortest stated
    period decides:
      * any stated period below the minimum answers false, whatever the others say;
      * a stated value that is not an ISO 8601 duration (a bare number, "unlimited", a zero
        duration) answers None: its unit or meaning is not documented, so it can neither pass
        nor fail the account;
      * otherwise, when delete-retention-period is stated and meets the minimum, the answer is
        true, including for a connector that states no snapshot retention of its own;
      * when delete-retention-period is not stated, the answer is true only if every connector
        states a snapshot retention that meets the minimum, and None if one does not.

    Proves: the retention Keepit applies, read from Keepit's own configuration. Does not prove:
    that a given item was ever backed up. An account with no cloud connectors answers false (no
    retention applies to nothing). An unreadable, empty, refused or partial body answers None
    (not measured), never false.
    """
    key = "isDeletionRetentionPeriodEnforced"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("raw XML body was not parsed by Integration-Service")
            return json.loads(text)
        return value

    def listify(value):
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return value
        return [value]

    def unwrap(value, marker):
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

    def read_resources(data):
        """name -> <limit> text from GET /users/{accountId}/resources, or (None, reason)."""
        if not isinstance(data, dict) or "resources" not in data:
            return None, "Response has no <resources> element (the /resources call did not run)"
        res = data.get("resources")
        if res is None or res == "":
            res = {}
        if not isinstance(res, dict):
            return None, "<resources> element has an unexpected shape"
        if res.get("error") is True:
            return None, "The /resources call was refused or failed, so the retention resources could not be read"
        out = {}
        for r in listify(res.get("resource")):
            if isinstance(r, dict) and r.get("name"):
                limit = r.get("limit")
                out[str(r.get("name")).strip()] = None if limit is None else str(limit).strip()
        return out, None

    def duration_days(text):
        """ISO 8601 duration (the documented "duration" resource type, e.g. P1Y, P30D, PT4H) in
        days, with a year as 365 and a month as 30 days. Anything else, and a zero duration
        (whose meaning Keepit does not document), returns None: unknown, never a pass."""
        if text is None:
            return None
        m = re.match(r"^P(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)W)?(?:(\d+(?:\.\d+)?)D)?(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$", str(text).strip().upper())
        if not m or str(text).strip().upper() in ["P", "PT"] or str(text).strip().upper().endswith("T"):
            return None
        parts = [float(g) if g else 0.0 for g in m.groups()]
        days = parts[0] * 365 + parts[1] * 30 + parts[2] * 7 + parts[3] + parts[4] / 24.0 + parts[5] / 1440.0 + parts[6] / 86400.0
        if days <= 0:
            return None
        return days

    def retention_rows(input):
        """(rows, deletion, None) or (None, None, reason).

        rows: effective snapshot retention for each cloud connector. deletion: the account's
        delete-retention-period resource as {"retention", "days"}, or None when it is not stated.

        Most specific value wins: the connector's own <backup-retention> (listDevices), then the
        product resource "<type>-snapshot-retention", then "generic-snapshot-retention"
        (GET /users/{accountId}/resources). Connector type "o365-admin" maps to the documented
        resource prefix "o365"; every other documented type is its own prefix.
        """
        data = unwrap(parse_input(input), "devices")
        if not isinstance(data, dict):
            return None, None, "Response is not an object"
        if data.get("error") is True:
            return None, None, "Integration-Service returned an error envelope"
        if "devices" not in data:
            return None, None, "Response has no <devices> element, so no connector could be read"
        resources, problem = read_resources(data)
        if resources is None:
            return None, None, problem
        devices = data.get("devices")
        if devices is None or devices == "":
            devices = {}
        if not isinstance(devices, dict):
            return None, None, "<devices> element has an unexpected shape"
        if devices.get("error") is True:
            return None, None, "The /devices call was refused or failed, so no connector could be read"
        deletion = None
        stated = resources.get("delete-retention-period")
        if stated not in [None, ""]:
            deletion = {"retention": stated, "days": duration_days(stated)}
        rows = []
        for c in listify(devices.get("cloud")):
            if not isinstance(c, dict):
                return None, None, "A connector entry could not be read, so the connector list is incomplete"
            kind = str(c.get("type") or "").strip()
            prefix = "o365" if kind == "o365-admin" else kind
            own = c.get("backup-retention")
            if own not in [None, ""]:
                value, source = str(own).strip(), "connector backup-retention"
            elif resources.get(prefix + "-snapshot-retention") not in [None, ""]:
                value, source = resources.get(prefix + "-snapshot-retention"), "product " + prefix + "-snapshot-retention"
            elif resources.get("generic-snapshot-retention") not in [None, ""]:
                value, source = resources.get("generic-snapshot-retention"), "product generic-snapshot-retention"
            else:
                value, source = None, "none found"
            name = str(c.get("name") or c.get("guid") or "")
            rows.append({"connector": name + " (" + kind + ")" if kind else name, "retention": value,
                         "source": source, "days": duration_days(value)})
        return rows, deletion, None

    def judge(rows, deletion, minimum_days, label):
        if len(rows) == 0:
            return False, "The account has no cloud connectors, so no retention applies"
        short = [r for r in rows if r["days"] is not None and r["days"] < minimum_days]
        deletion_short = deletion is not None and deletion["days"] is not None and deletion["days"] < minimum_days
        if deletion_short or short:
            parts = []
            if deletion_short:
                parts.append("delete-retention-period is " + str(deletion["retention"]) + ", a deleted connector or user is recoverable for less than " + label)
            if short:
                parts.append(str(len(short)) + " of " + str(len(rows)) + " cloud connectors keep snapshots for less than " + label)
            return False, "; ".join(parts)
        unreadable = [r for r in rows if r["retention"] is not None and r["days"] is None]
        unstated = [r for r in rows if r["retention"] is None]
        if deletion is not None and deletion["days"] is None:
            return None, "delete-retention-period is " + str(deletion["retention"]) + ", which is not an ISO 8601 duration, so the deletion retention could not be read"
        if unreadable:
            return None, str(len(unreadable)) + " of " + str(len(rows)) + " cloud connectors state a snapshot retention that is not an ISO 8601 duration, so the retention could not be read"
        if deletion is not None:
            reason = "delete-retention-period is " + str(deletion["retention"]) + ", a deleted connector or user stays recoverable for at least " + label
            if len(rows) > len(unstated):
                reason += "; every snapshot retention Keepit states is also at least that long"
            return True, reason
        if unstated:
            return None, str(len(unstated)) + " of " + str(len(rows)) + " cloud connectors state no snapshot retention and delete-retention-period is not stated, so no retention could be read"
        return True, "All " + str(len(rows)) + " cloud connectors keep snapshots for at least " + label

    try:
        rows, deletion, problem = retention_rows(input)
        if rows is None:
            return {key: None, "reason": problem}
        result, reason = judge(rows, deletion, 30, "one month (30 days)")
        return {
            key: result,
            "reason": reason,
            "minimumDays": 30,
            "deleteRetentionPeriod": deletion,
            "connectors": rows,
        }
    except Exception as e:
        return {key: None, "error": str(e)}


def envelope(key, method, bare):
    """Wrap a bare result in the platform envelope.

    Whether the criterion was measured is read from its value alone: None means the body could
    not answer the check, so dataCollection reports an error and Token-Service does not grade
    it. Every other value, including a measured False, reports success.
    """
    value = bare.get(key)
    reason = str(bare.get("reason") or bare.get("error") or "The response could not answer this check")
    measured = value is not None
    passed = value is True or value == "confirmed"
    return {
        "transformedResponse": bare,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Keepit", "product": "Keepit", "method": method,
                         "evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0"},
        },
    }


def transform(input):
    """transform_bare() in the platform envelope; a None criterion reports a dataCollection error."""
    return envelope(KEY, METHOD, transform_bare(input))
