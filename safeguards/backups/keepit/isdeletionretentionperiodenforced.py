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
#           generic-snapshot-retention and <type>-snapshot-retention, type "duration",
#           "Keep snapshots ... no more than this period"
#
# An item deleted at the source stays recoverable in Keepit for as long as a snapshot that
# holds it is kept, so the snapshot retention is the deletion-retention window.

import json
import re


def transform(input):
    """
    True when every cloud connector's effective snapshot retention is at least one month
    (30 days), so an item deleted at the source stays recoverable for at least that long.

    Proves: the retention Keepit applies to each connector, read from Keepit's own
    configuration. Does not prove: that a given item was ever backed up. A connector with no
    readable retention, a retention that is not an ISO 8601 duration, or an unreadable body
    answers false.
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
        """Effective snapshot retention for each cloud connector, or (None, reason).

        Most specific value wins: the connector's own <backup-retention> (listDevices), then the
        product resource "<type>-snapshot-retention", then "generic-snapshot-retention"
        (GET /users/{accountId}/resources). Connector type "o365-admin" maps to the documented
        resource prefix "o365"; every other documented type is its own prefix.
        """
        data = unwrap(parse_input(input), "devices")
        if not isinstance(data, dict):
            return None, "Response is not an object"
        if data.get("error") is True:
            return None, "Integration-Service returned an error envelope"
        if "devices" not in data:
            return None, "Response has no <devices> element, so no connector could be read"
        resources, problem = read_resources(data)
        if resources is None:
            return None, problem
        devices = data.get("devices")
        if devices is None or devices == "":
            devices = {}
        if not isinstance(devices, dict):
            return None, "<devices> element has an unexpected shape"
        rows = []
        for c in listify(devices.get("cloud")):
            if not isinstance(c, dict):
                continue
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
        return rows, None

    def judge(rows, minimum_days, label):
        if len(rows) == 0:
            return False, "The account has no cloud connectors, so no retention applies"
        short = [r for r in rows if r["days"] is not None and r["days"] < minimum_days]
        unknown = [r for r in rows if r["days"] is None]
        if short:
            return False, str(len(short)) + " of " + str(len(rows)) + " cloud connectors keep snapshots for less than " + label
        if unknown:
            return False, str(len(unknown)) + " of " + str(len(rows)) + " cloud connectors have no readable retention (missing or not an ISO 8601 duration)"
        return True, "All " + str(len(rows)) + " cloud connectors keep snapshots for at least " + label

    try:
        rows, problem = retention_rows(input)
        if rows is None:
            return {key: False, "reason": problem}
        result, reason = judge(rows, 30, "one month (30 days)")
        return {
            key: result,
            "reason": reason,
            "minimumDays": 30,
            "connectors": rows,
        }
    except Exception as e:
        return {key: False, "error": str(e)}
